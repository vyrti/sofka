//! Optional Popeye CLI discovery, execution, and report parsing.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::de::{DeserializeSeed, Error as _, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use tokio::io::AsyncReadExt;
use tokio_util::io::SyncIoBridge;

const EXECUTABLES: &[&str] = &["popeye", "kubectl-popeye"];
#[cfg(not(test))]
const SCAN_TIMEOUT: Duration = Duration::from_secs(5 * 60);
#[cfg(test)]
const SCAN_TIMEOUT: Duration = Duration::from_secs(1);
const STDERR_MAX_BYTES: usize = 64 * 1024;
const STDERR_CHUNK_BYTES: usize = 8 * 1024;
#[cfg(not(test))]
const REPORT_MAX_LINES: usize = 10_000;
#[cfg(test)]
const REPORT_MAX_LINES: usize = 256;
#[cfg(not(test))]
const REPORT_MAX_BYTES: usize = 4 * 1024 * 1024;
#[cfg(test)]
const REPORT_MAX_BYTES: usize = 64 * 1024;
const TRUNCATION_LINE: &str = "… report truncated to protect memory";

/// A report already reduced to what the document view needs.
#[derive(Debug)]
pub struct ReportView {
    pub title: String,
    pub lines: Vec<String>,
    pub score: i64,
    pub grade: String,
}

/// Find a standalone or Krew-installed Popeye executable on the process PATH.
pub fn detect() -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| detect_in_path(&path))
}

/// PATH-parameterized detection keeps the hot-reload behavior testable without
/// mutating the process environment shared by Rust's parallel test runner.
pub fn detect_in_path(path: &OsStr) -> Option<PathBuf> {
    for dir in std::env::split_paths(path) {
        for name in EXECUTABLES {
            let candidate = dir.join(name);
            if is_executable(&candidate) {
                return Some(absolute(candidate));
            }
        }
    }
    None
}

fn absolute(path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(&path))
            .unwrap_or(path)
    }
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

fn configure_command(command: &mut tokio::process::Command, context: &str, namespace: &str) {
    command.args([
        "--out",
        "json",
        "--force-exit-zero",
        "--log-level",
        "0",
        "--logs",
        "none",
    ]);
    if !context.is_empty() {
        command.arg("--context").arg(context);
    }
    if namespace.is_empty() {
        command.arg("--all-namespaces");
    } else {
        command.arg("--namespace").arg(namespace);
    }
}

/// Run Popeye with bounded output memory and a hard deadline. JSON is parsed
/// directly from the child pipe on one blocking worker so no full document or
/// intermediate chunk queue is allocated.
pub async fn scan(
    executable: PathBuf,
    context: String,
    namespace: String,
) -> Result<ReportView, String> {
    scan_with_timeout(executable, context, namespace, SCAN_TIMEOUT).await
}

async fn scan_with_timeout(
    executable: PathBuf,
    context: String,
    namespace: String,
    timeout: Duration,
) -> Result<ReportView, String> {
    tokio::time::timeout(timeout, scan_inner(executable, context, namespace))
        .await
        .map_err(|_| format!("Popeye scan timed out after {} seconds", timeout.as_secs()))?
}

async fn scan_inner(
    executable: PathBuf,
    context: String,
    namespace: String,
) -> Result<ReportView, String> {
    let mut command = tokio::process::Command::new(&executable);
    configure_command(&mut command, &context, &namespace);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|e| format!("failed to start {}: {e}", executable.display()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "failed to capture Popeye stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "failed to capture Popeye stderr".to_string())?;

    let parse_task = tokio::task::spawn_blocking(move || {
        parse_reader(SyncIoBridge::new(stdout), &context, &namespace)
    });
    let stderr_task = tokio::spawn(read_stderr(stderr));

    let status = child
        .wait()
        .await
        .map_err(|e| format!("failed while waiting for Popeye: {e}"))?;
    let stderr = stderr_task
        .await
        .map_err(|e| format!("Popeye error reader failed: {e}"))?
        .unwrap_or_default();
    let parsed = parse_task
        .await
        .map_err(|e| format!("Popeye JSON parser failed: {e}"))?;

    if !status.success() {
        let detail = first_line(&stderr).unwrap_or("no error output");
        return Err(format!("Popeye exited {status}: {detail}"));
    }
    parsed
}

async fn read_stderr(mut stderr: tokio::process::ChildStderr) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chunk = [0; STDERR_CHUNK_BYTES];
    loop {
        let read = stderr.read(&mut chunk).await?;
        if read == 0 {
            return Ok(bytes);
        }
        let keep = read.min(STDERR_MAX_BYTES.saturating_sub(bytes.len()));
        bytes.extend_from_slice(&chunk[..keep]);
    }
}

fn first_line(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(bytes)
        .ok()?
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
}

struct BoundedLines {
    lines: Vec<String>,
    bytes: usize,
    max_lines: usize,
    max_bytes: usize,
    truncated: bool,
}

impl Default for BoundedLines {
    fn default() -> Self {
        Self::with_limits(REPORT_MAX_LINES, REPORT_MAX_BYTES)
    }
}

impl BoundedLines {
    fn with_limits(max_lines: usize, max_bytes: usize) -> Self {
        Self {
            lines: Vec::new(),
            bytes: 0,
            max_lines,
            max_bytes,
            truncated: false,
        }
    }

    fn accepting(&self) -> bool {
        !self.truncated && self.can_push(0)
    }

    fn can_push(&self, len: usize) -> bool {
        self.lines.len() < self.max_lines.saturating_sub(1)
            && self
                .bytes
                .checked_add(len)
                .is_some_and(|bytes| bytes <= self.max_bytes.saturating_sub(TRUNCATION_LINE.len()))
    }

    fn push(&mut self, line: String) -> bool {
        if self.truncated || !self.can_push(line.len()) {
            self.truncated = true;
            return false;
        }
        self.bytes += line.len();
        self.lines.push(line);
        true
    }

    fn push_static(&mut self, line: &str) -> bool {
        if self.truncated || !self.can_push(line.len()) {
            self.truncated = true;
            return false;
        }
        self.bytes += line.len();
        self.lines.push(line.into());
        true
    }

    fn push_prefixed(&mut self, prefix: &str, mut value: String) -> bool {
        let Some(len) = prefix.len().checked_add(value.len()) else {
            self.truncated = true;
            return false;
        };
        if self.truncated || !self.can_push(len) {
            self.truncated = true;
            return false;
        }
        value.reserve(prefix.len());
        value.insert_str(0, prefix);
        self.bytes += value.len();
        self.lines.push(value);
        true
    }

    fn append(&mut self, other: Self) {
        let other_truncated = other.truncated;
        for line in other.lines {
            if !self.push(line) {
                break;
            }
        }
        self.truncated |= other_truncated;
    }

    fn truncate(&mut self) {
        self.truncated = true;
    }

    fn finish(mut self) -> Vec<String> {
        if self.truncated
            && self.lines.len() < self.max_lines
            && self.bytes + TRUNCATION_LINE.len() <= self.max_bytes
        {
            self.lines.push(TRUNCATION_LINE.into());
        }
        self.lines
    }
}

#[derive(Deserialize)]
struct Envelope {
    popeye: Report,
    #[serde(rename = "ClusterName", default)]
    cluster_name: String,
    #[serde(rename = "ContextName", default)]
    context_name: String,
}

struct Report {
    report_time: String,
    score: i64,
    grade: String,
    body: BoundedLines,
    sections: usize,
    errors: usize,
}

#[derive(Deserialize)]
#[serde(field_identifier)]
enum ReportField {
    #[serde(rename = "report_time")]
    ReportTime,
    #[serde(rename = "score")]
    Score,
    #[serde(rename = "grade")]
    Grade,
    #[serde(rename = "sections")]
    Sections,
    #[serde(rename = "errors")]
    Errors,
    #[serde(other)]
    Other,
}

impl<'de> Deserialize<'de> for Report {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ReportVisitor;

        impl<'de> Visitor<'de> for ReportVisitor {
            type Value = Report;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Popeye report object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut report_time = None;
                let mut score = None;
                let mut grade = None;
                let mut body = BoundedLines::default();
                let mut sections = 0;
                let mut errors = 0;

                while let Some(field) = map.next_key()? {
                    match field {
                        ReportField::ReportTime => report_time = Some(map.next_value()?),
                        ReportField::Score => score = Some(map.next_value()?),
                        ReportField::Grade => grade = Some(map.next_value()?),
                        ReportField::Sections => {
                            map.next_value_seed(SectionsSeed {
                                body: &mut body,
                                count: &mut sections,
                            })?;
                        }
                        ReportField::Errors => {
                            map.next_value_seed(ErrorsSeed {
                                body: &mut body,
                                count: &mut errors,
                            })?;
                        }
                        ReportField::Other => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }

                Ok(Report {
                    report_time: report_time.unwrap_or_default(),
                    score: score.ok_or_else(|| M::Error::missing_field("score"))?,
                    grade: grade.unwrap_or_default(),
                    body,
                    sections,
                    errors,
                })
            }
        }

        deserializer.deserialize_map(ReportVisitor)
    }
}

#[derive(Default, Deserialize)]
struct Tally {
    #[serde(default)]
    ok: usize,
    #[serde(default)]
    info: usize,
    #[serde(default, rename = "warning")]
    warnings: usize,
    #[serde(default)]
    error: usize,
    #[serde(default)]
    score: i64,
}

#[derive(Deserialize)]
struct Issue {
    #[serde(default)]
    level: i64,
    #[serde(default)]
    message: String,
}

struct SectionsSeed<'a> {
    body: &'a mut BoundedLines,
    count: &'a mut usize,
}

impl<'de> DeserializeSeed<'de> for SectionsSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SectionsVisitor<'a> {
            body: &'a mut BoundedLines,
            count: &'a mut usize,
        }

        impl<'de> Visitor<'de> for SectionsVisitor<'_> {
            type Value = ();

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Popeye sections array")
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                while self.body.accepting() {
                    let Some(section) = seq.next_element::<Section>()? else {
                        return Ok(());
                    };
                    *self.count += 1;
                    render_section(self.body, section);
                }
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    self.body.truncate();
                    while seq.next_element::<IgnoredAny>()?.is_some() {}
                }
                Ok(())
            }
        }

        deserializer.deserialize_seq(SectionsVisitor {
            body: self.body,
            count: self.count,
        })
    }
}

#[derive(Deserialize)]
struct Section {
    linter: String,
    #[serde(default)]
    gvr: String,
    #[serde(default)]
    tally: Tally,
    #[serde(default)]
    issues: RenderedIssues,
}

#[derive(Default)]
struct RenderedIssues(BoundedLines);

impl<'de> Deserialize<'de> for RenderedIssues {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IssuesVisitor;

        impl<'de> Visitor<'de> for IssuesVisitor {
            type Value = RenderedIssues;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Popeye resource-to-issues object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut lines = BoundedLines::default();
                while lines.accepting() {
                    let Some(resource) = map.next_key::<String>()? else {
                        return Ok(RenderedIssues(lines));
                    };
                    lines.push_prefixed("  ", resource);
                    map.next_value_seed(IssueListSeed { lines: &mut lines })?;
                }
                if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
                    lines.truncate();
                    while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                }
                Ok(RenderedIssues(lines))
            }
        }

        deserializer.deserialize_map(IssuesVisitor)
    }
}

struct IssueListSeed<'a> {
    lines: &'a mut BoundedLines,
}

impl<'de> DeserializeSeed<'de> for IssueListSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IssueListVisitor<'a> {
            lines: &'a mut BoundedLines,
        }

        impl<'de> Visitor<'de> for IssueListVisitor<'_> {
            type Value = ();

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Popeye issue array")
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                while self.lines.accepting() {
                    let Some(issue) = seq.next_element::<Issue>()? else {
                        return Ok(());
                    };
                    let prefix = match issue.level {
                        3 => "    ERROR ",
                        2 => "    WARNING ",
                        1 => "    INFO ",
                        _ => "    OK ",
                    };
                    self.lines.push_prefixed(prefix, issue.message);
                }
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    self.lines.truncate();
                    while seq.next_element::<IgnoredAny>()?.is_some() {}
                }
                Ok(())
            }
        }

        deserializer.deserialize_seq(IssueListVisitor { lines: self.lines })
    }
}

struct ErrorsSeed<'a> {
    body: &'a mut BoundedLines,
    count: &'a mut usize,
}

impl<'de> DeserializeSeed<'de> for ErrorsSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ErrorsVisitor<'a> {
            body: &'a mut BoundedLines,
            count: &'a mut usize,
        }

        impl<'de> Visitor<'de> for ErrorsVisitor<'_> {
            type Value = ();

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Popeye errors object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                while self.body.accepting() {
                    let Some((_key, error)) = map.next_entry::<IgnoredAny, String>()? else {
                        return Ok(());
                    };
                    if *self.count == 0 {
                        self.body.push_static("");
                        self.body.push_static("Report errors");
                    }
                    *self.count += 1;
                    self.body.push_prefixed("  ERROR ", error);
                }
                if map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
                    self.body.truncate();
                    while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                }
                Ok(())
            }
        }

        deserializer.deserialize_map(ErrorsVisitor {
            body: self.body,
            count: self.count,
        })
    }
}

fn render_section(lines: &mut BoundedLines, section: Section) {
    if !lines.push_static("") {
        return;
    }
    let mut heading = section.linter;
    let _ = write!(heading, " — {}%", section.tally.score);
    if !section.gvr.is_empty() {
        let _ = write!(heading, " ({})", section.gvr);
    }
    if !lines.push(heading) {
        return;
    }
    if !lines.push(format!(
        "  ok {} · info {} · warning {} · error {}",
        section.tally.ok, section.tally.info, section.tally.warnings, section.tally.error
    )) {
        return;
    }
    lines.append(section.issues.0);
}

fn parse_reader(
    reader: impl Read,
    requested_context: &str,
    requested_namespace: &str,
) -> Result<ReportView, String> {
    let envelope: Envelope =
        serde_json::from_reader(reader).map_err(|e| format!("invalid JSON from Popeye: {e}"))?;
    Ok(format_report(
        envelope,
        requested_context,
        requested_namespace,
    ))
}

fn format_report(
    envelope: Envelope,
    requested_context: &str,
    requested_namespace: &str,
) -> ReportView {
    let Report {
        report_time,
        score,
        grade,
        body,
        sections,
        errors,
    } = envelope.popeye;
    let mut lines = BoundedLines::default();
    lines.push_static("Summary");
    lines.push(format!("  score:      {score}% ({grade})"));
    let context = if envelope.context_name.is_empty() {
        requested_context
    } else {
        &envelope.context_name
    };
    if !context.is_empty() {
        lines.push(format!("  context:    {context}"));
    }
    if !envelope.cluster_name.is_empty() {
        lines.push_prefixed("  cluster:    ", envelope.cluster_name);
    }
    lines.push(format!(
        "  namespace:  {}",
        if requested_namespace.is_empty() {
            "all"
        } else {
            requested_namespace
        }
    ));
    if !report_time.is_empty() {
        lines.push_prefixed("  scanned:    ", report_time);
    }
    lines.append(body);
    if sections == 0 && errors == 0 {
        lines.push_static("");
        lines.push_static("No linter sections were returned.");
    }

    ReportView {
        title: format!("popeye — {score}% ({grade})"),
        lines: lines.finish(),
        score,
        grade,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_is_scoped_to_context_and_namespace_without_an_argument_copy() {
        let mut command = tokio::process::Command::new("popeye");
        configure_command(&mut command, "prod", "apps");
        assert_eq!(
            command.as_std().get_args().collect::<Vec<_>>(),
            [
                "--out",
                "json",
                "--force-exit-zero",
                "--log-level",
                "0",
                "--logs",
                "none",
                "--context",
                "prod",
                "--namespace",
                "apps",
            ]
        );

        let mut command = tokio::process::Command::new("popeye");
        configure_command(&mut command, "", "");
        assert!(
            command
                .as_std()
                .get_args()
                .last()
                .is_some_and(|arg| arg == "--all-namespaces")
        );
    }

    #[test]
    fn parses_and_formats_current_json_schema() {
        let json = r#"{
            "popeye": {
                "report_time": "2026-09-06T12:00:00Z",
                "score": 72,
                "grade": "C",
                "sections": [{
                    "linter": "pods",
                    "gvr": "v1/pods",
                    "tally": {"ok": 2, "info": 1, "warning": 1, "error": 1, "score": 50},
                    "issues": {"apps/web": [
                        {"group": "apps", "gvr": "v1/pods", "level": 3, "message": "[POP-106] CrashLoopBackOff"},
                        {"group": "apps", "gvr": "v1/pods", "level": 2, "message": "[POP-107] No probes"}
                    ]}
                }],
                "errors": {"error": "metrics unavailable"},
                "future_field": true
            },
            "ClusterName": "prod-cluster",
            "ContextName": "prod"
        }"#;
        let view = parse_reader(json.as_bytes(), "ignored", "apps").unwrap();
        assert_eq!(view.score, 72);
        assert_eq!(view.grade, "C");
        assert_eq!(view.title, "popeye — 72% (C)");
        assert!(view.lines.iter().any(|line| line == "  context:    prod"));
        assert!(
            view.lines
                .iter()
                .any(|line| line.contains("ERROR [POP-106] CrashLoopBackOff"))
        );
        assert!(
            view.lines
                .iter()
                .any(|line| line == "  ERROR metrics unavailable")
        );
    }

    #[test]
    fn rendered_output_has_strict_line_and_byte_limits() {
        let mut lines = BoundedLines::with_limits(3, 64);
        assert!(lines.push_static("first"));
        assert!(lines.push_static("second"));
        assert!(!lines.push_static("third"));
        let lines = lines.finish();
        assert_eq!(lines, ["first", "second", TRUNCATION_LINE]);
        assert!(lines.len() <= 3);
        assert!(lines.iter().map(String::len).sum::<usize>() <= 64);

        let mut lines = BoundedLines::with_limits(10, TRUNCATION_LINE.len() + 4);
        assert!(!lines.push_static("12345"));
        let lines = lines.finish();
        assert_eq!(lines, [TRUNCATION_LINE]);
        assert!(lines.iter().map(String::len).sum::<usize>() <= TRUNCATION_LINE.len() + 4);
    }

    #[test]
    fn malformed_json_is_actionable() {
        let error = parse_reader("not json".as_bytes(), "", "").err().unwrap();
        assert!(error.starts_with("invalid JSON from Popeye:"), "{error}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn scan_timeout_stops_a_hung_process() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "sofka-popeye-timeout-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let executable = root.join("popeye");
        std::fs::write(&executable, "#!/bin/sh\nexec sleep 60\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();

        let error = scan_with_timeout(
            executable,
            String::new(),
            String::new(),
            Duration::from_millis(25),
        )
        .await
        .unwrap_err();
        assert!(error.starts_with("Popeye scan timed out"), "{error}");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn path_detection_requires_an_executable_and_honours_path_order() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "sofka-popeye-path-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let first = root.join("first");
        let second = root.join("second");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        std::fs::write(first.join("popeye"), "not executable").unwrap();
        let plugin = second.join("kubectl-popeye");
        std::fs::write(&plugin, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&plugin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = std::env::join_paths([&first, &second]).unwrap();
        assert_eq!(detect_in_path(&path), Some(plugin));
        std::fs::remove_dir_all(root).unwrap();
    }
}
