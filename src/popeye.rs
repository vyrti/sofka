//! Optional Popeye CLI discovery, execution, and report parsing.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

const EXECUTABLES: &[&str] = &["popeye", "kubectl-popeye"];
const PIPE_CHUNK_BYTES: usize = 16 * 1024;
const PIPE_CHUNKS: usize = 2;
const STDERR_MAX_BYTES: u64 = 64 * 1024;

/// A report already reduced to what the document view needs.
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

/// Arguments for one scan, scoped exactly like the active Sofka view.
pub fn args(context: &str, namespace: &str) -> Vec<String> {
    let mut args = vec![
        "--out".into(),
        "json".into(),
        "--force-exit-zero".into(),
        "--log-level".into(),
        "0".into(),
        "--logs".into(),
        "none".into(),
    ];
    if !context.is_empty() {
        args.extend(["--context".into(), context.into()]);
    }
    if namespace.is_empty() {
        args.push("--all-namespaces".into());
    } else {
        args.extend(["--namespace".into(), namespace.into()]);
    }
    args
}

/// Run Popeye without buffering its JSON document in memory. Async stdout is
/// bridged to serde's synchronous streaming reader with two bounded chunks;
/// parsing and report formatting stay off the UI runtime thread.
pub async fn scan(
    executable: PathBuf,
    context: String,
    namespace: String,
) -> Result<ReportView, String> {
    let argv = args(&context, &namespace);
    let mut command = tokio::process::Command::new(&executable);
    command
        .args(&argv)
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

    let (chunk_tx, chunk_rx) = mpsc::channel(PIPE_CHUNKS);
    let stdout_task = tokio::spawn(pump_stdout(stdout, chunk_tx));
    let parse_context = context.clone();
    let parse_namespace = namespace.clone();
    let parse_task = tokio::task::spawn_blocking(move || {
        let reader = ChunkReader::new(chunk_rx);
        parse_reader(reader, &parse_context, &parse_namespace)
    });
    let stderr_task = tokio::spawn(read_stderr(stderr));

    let status = child
        .wait()
        .await
        .map_err(|e| format!("failed while waiting for Popeye: {e}"))?;
    let pump_result = stdout_task
        .await
        .map_err(|e| format!("Popeye output reader failed: {e}"))?;
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
    pump_result.map_err(|e| format!("failed reading Popeye output: {e}"))?;
    parsed
}

async fn pump_stdout(
    mut stdout: tokio::process::ChildStdout,
    tx: mpsc::Sender<Vec<u8>>,
) -> io::Result<()> {
    loop {
        let mut chunk = vec![0; PIPE_CHUNK_BYTES];
        let n = stdout.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        chunk.truncate(n);
        if tx.send(chunk).await.is_err() {
            return Ok(());
        }
    }
}

async fn read_stderr(stderr: tokio::process::ChildStderr) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    stderr
        .take(STDERR_MAX_BYTES)
        .read_to_end(&mut bytes)
        .await?;
    Ok(bytes)
}

fn first_line(bytes: &[u8]) -> Option<&str> {
    std::str::from_utf8(bytes)
        .ok()?
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
}

struct ChunkReader {
    rx: mpsc::Receiver<Vec<u8>>,
    chunk: Vec<u8>,
    offset: usize,
}

impl ChunkReader {
    fn new(rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            rx,
            chunk: Vec::new(),
            offset: 0,
        }
    }
}

impl Read for ChunkReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.offset < self.chunk.len() {
                let n = buf.len().min(self.chunk.len() - self.offset);
                buf[..n].copy_from_slice(&self.chunk[self.offset..self.offset + n]);
                self.offset += n;
                return Ok(n);
            }
            match self.rx.blocking_recv() {
                Some(chunk) => {
                    self.chunk = chunk;
                    self.offset = 0;
                }
                None => return Ok(0),
            }
        }
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

#[derive(Deserialize)]
struct Report {
    #[serde(default)]
    report_time: String,
    score: i64,
    #[serde(default)]
    grade: String,
    #[serde(default)]
    sections: Vec<Section>,
    #[serde(default)]
    errors: ReportErrors,
}

#[derive(Deserialize)]
struct Section {
    linter: String,
    #[serde(default)]
    gvr: String,
    #[serde(default)]
    tally: Tally,
    #[serde(default)]
    issues: IssueGroups,
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

#[derive(Default)]
struct IssueGroups(Vec<(String, Vec<Issue>)>);

impl<'de> Deserialize<'de> for IssueGroups {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct GroupsVisitor;

        impl<'de> Visitor<'de> for GroupsVisitor {
            type Value = IssueGroups;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Popeye resource-to-issues object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut groups = Vec::with_capacity(map.size_hint().unwrap_or(0));
                while let Some(entry) = map.next_entry()? {
                    groups.push(entry);
                }
                Ok(IssueGroups(groups))
            }
        }

        deserializer.deserialize_map(GroupsVisitor)
    }
}

#[derive(Default)]
struct ReportErrors(Vec<String>);

impl<'de> Deserialize<'de> for ReportErrors {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ErrorsVisitor;

        impl<'de> Visitor<'de> for ErrorsVisitor {
            type Value = ReportErrors;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Popeye errors object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut errors = Vec::with_capacity(map.size_hint().unwrap_or(0));
                while let Some((_key, error)) = map.next_entry::<IgnoredAny, String>()? {
                    errors.push(error);
                }
                Ok(ReportErrors(errors))
            }
        }

        deserializer.deserialize_map(ErrorsVisitor)
    }
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
        sections,
        errors,
    } = envelope.popeye;
    let issue_count = sections
        .iter()
        .flat_map(|section| &section.issues.0)
        .map(|(_, issues)| issues.len())
        .sum::<usize>();
    let empty_report = sections.is_empty() && errors.0.is_empty();
    let mut lines = Vec::with_capacity(12 + sections.len() * 2 + issue_count * 2);
    lines.push("Summary".into());
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
        lines.push(format!("  cluster:    {}", envelope.cluster_name));
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
        lines.push(format!("  scanned:    {report_time}"));
    }

    for section in sections {
        lines.push(String::new());
        let mut heading = format!("{} — {}%", section.linter, section.tally.score);
        if !section.gvr.is_empty() {
            let _ = write!(heading, " ({})", section.gvr);
        }
        lines.push(heading);
        lines.push(format!(
            "  ok {} · info {} · warning {} · error {}",
            section.tally.ok, section.tally.info, section.tally.warnings, section.tally.error
        ));
        for (resource, issues) in section.issues.0 {
            lines.push(format!("  {resource}"));
            for issue in issues {
                let level = match issue.level {
                    3 => "ERROR",
                    2 => "WARNING",
                    1 => "INFO",
                    _ => "OK",
                };
                lines.push(format!("    {level} {}", issue.message));
            }
        }
    }

    if !errors.0.is_empty() {
        lines.push(String::new());
        lines.push("Report errors".into());
        for error in errors.0 {
            lines.push(format!("  ERROR {error}"));
        }
    }
    if empty_report {
        lines.push(String::new());
        lines.push("No linter sections were returned.".into());
    }

    ReportView {
        title: format!("popeye — {score}% ({grade})"),
        lines,
        score,
        grade,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_is_scoped_to_context_and_namespace() {
        assert_eq!(
            args("prod", "apps"),
            vec![
                "--out".to_string(),
                "json".to_string(),
                "--force-exit-zero".to_string(),
                "--log-level".to_string(),
                "0".to_string(),
                "--logs".to_string(),
                "none".to_string(),
                "--context".to_string(),
                "prod".to_string(),
                "--namespace".to_string(),
                "apps".to_string(),
            ]
        );
        assert!(args("", "").ends_with(&["--all-namespaces".into()]));
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
    fn malformed_json_is_actionable() {
        let error = parse_reader("not json".as_bytes(), "", "").err().unwrap();
        assert!(error.starts_with("invalid JSON from Popeye:"), "{error}");
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
