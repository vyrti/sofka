//! Optional Trivy CLI discovery, execution, and Kubernetes report parsing.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use tokio::io::{AsyncRead, AsyncReadExt};

const EXECUTABLE: &str = "trivy";
const SCAN_TIMEOUT: Duration = Duration::from_secs(5 * 60);
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
    pub findings: usize,
    pub critical: usize,
    pub high: usize,
    pub truncated: bool,
}

/// Find Trivy on the process PATH.
pub fn detect() -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| detect_in_path(&path))
}

/// PATH-parameterized detection keeps reload behavior testable without
/// mutating the process environment shared by Rust's parallel test runner.
pub fn detect_in_path(path: &OsStr) -> Option<PathBuf> {
    std::env::split_paths(path)
        .map(|dir| dir.join(EXECUTABLE))
        .find(|candidate| is_executable(candidate))
        .map(absolute)
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
        "kubernetes",
        "--format",
        "json",
        "--report",
        "summary",
        "--quiet",
        "--disable-telemetry",
        "--skip-version-check",
        "--no-progress",
        "--parallel",
        "1",
        "--list-all-pkgs=false",
        "--disable-node-collector",
        "--timeout",
        "5m",
    ]);
    if !namespace.is_empty() {
        command.arg("--include-namespaces").arg(namespace);
    }
    if !context.is_empty() {
        // Trivy defines CONTEXT as the command's sole positional argument.
        command.arg(context);
    }
}

/// Run Trivy with bounded output memory and a hard deadline. JSON is parsed
/// directly from the child pipe on one blocking worker so no full document or
/// intermediate chunk queue is allocated.
pub async fn scan(
    executable: PathBuf,
    context: String,
    namespace: String,
) -> Result<ReportView, String> {
    scan_with_timeout(executable, context, namespace, SCAN_TIMEOUT).await
}

pub(crate) async fn scan_with_timeout(
    executable: PathBuf,
    context: String,
    namespace: String,
    timeout: Duration,
) -> Result<ReportView, String> {
    tokio::time::timeout(timeout, scan_inner(executable, context, namespace))
        .await
        .map_err(|_| format!("Trivy scan timed out after {} seconds", timeout.as_secs()))?
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
        .ok_or_else(|| "failed to capture Trivy stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "failed to capture Trivy stderr".to_string())?;

    let runtime = tokio::runtime::Handle::current();
    let parse_task = tokio::task::spawn_blocking(move || {
        parse_reader(BlockingReader::new(stdout, runtime), &context, &namespace)
    });
    let stderr_task = tokio::spawn(read_stderr(stderr));

    let status = child
        .wait()
        .await
        .map_err(|e| format!("failed while waiting for Trivy: {e}"))?;
    let stderr = stderr_task
        .await
        .map_err(|e| format!("Trivy error reader failed: {e}"))?
        .unwrap_or_default();
    let parsed = parse_task
        .await
        .map_err(|e| format!("Trivy JSON parser failed: {e}"))?;

    if !status.success() {
        let detail = first_line(&stderr).unwrap_or("no error output");
        return Err(format!("Trivy exited {status}: {detail}"));
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

struct BlockingReader<R> {
    inner: R,
    runtime: tokio::runtime::Handle,
}

impl<R> BlockingReader<R> {
    fn new(inner: R, runtime: tokio::runtime::Handle) -> Self {
        Self { inner, runtime }
    }
}

impl<R: AsyncRead + Unpin> Read for BlockingReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.runtime.block_on(self.inner.read(bytes))
    }
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

#[derive(Clone, Copy, Debug, Default, Deserialize)]
enum Severity {
    #[serde(rename = "CRITICAL")]
    Critical,
    #[serde(rename = "HIGH")]
    High,
    #[serde(rename = "MEDIUM")]
    Medium,
    #[serde(rename = "LOW")]
    Low,
    #[default]
    #[serde(other)]
    Unknown,
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Clone, Copy, Default)]
struct Counts {
    vulnerabilities: usize,
    misconfigurations: usize,
    secrets: usize,
    errors: usize,
    critical: usize,
    high: usize,
    medium: usize,
    low: usize,
    unknown: usize,
}

impl Counts {
    fn record(&mut self, kind: FindingKind, severity: Severity) {
        match kind {
            FindingKind::Vulnerability => self.vulnerabilities += 1,
            FindingKind::Misconfiguration => self.misconfigurations += 1,
            FindingKind::Secret => self.secrets += 1,
        }
        match severity {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Unknown => self.unknown += 1,
        }
    }

    fn merge(&mut self, other: Self) {
        self.vulnerabilities += other.vulnerabilities;
        self.misconfigurations += other.misconfigurations;
        self.secrets += other.secrets;
        self.errors += other.errors;
        self.critical += other.critical;
        self.high += other.high;
        self.medium += other.medium;
        self.low += other.low;
        self.unknown += other.unknown;
    }

    fn findings(self) -> usize {
        self.vulnerabilities + self.misconfigurations + self.secrets
    }
}

#[derive(Clone, Copy)]
enum FindingKind {
    Vulnerability,
    Misconfiguration,
    Secret,
}

#[derive(Deserialize)]
struct Envelope {
    #[serde(rename = "ClusterName", default)]
    cluster_name: String,
    #[serde(rename = "Findings", alias = "Resources", default)]
    findings: RenderedFindings,
}

#[derive(Default)]
struct RenderedFindings {
    lines: BoundedLines,
    counts: Counts,
    resources: usize,
}

impl<'de> Deserialize<'de> for RenderedFindings {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct FindingsVisitor;

        impl<'de> Visitor<'de> for FindingsVisitor {
            type Value = RenderedFindings;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Trivy findings array")
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                let mut rendered = RenderedFindings::default();
                while rendered.lines.accepting() {
                    let Some(finding) = seq.next_element::<Finding>()? else {
                        return Ok(rendered);
                    };
                    render_finding(&mut rendered, finding);
                }
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    rendered.lines.truncate();
                    while seq.next_element::<IgnoredAny>()?.is_some() {}
                }
                Ok(rendered)
            }
        }

        deserializer.deserialize_seq(FindingsVisitor)
    }
}

#[derive(Deserialize)]
struct Finding {
    #[serde(rename = "Namespace", default)]
    namespace: String,
    #[serde(rename = "Kind", default)]
    kind: String,
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Results", default)]
    results: RenderedResults,
    #[serde(rename = "Error", default)]
    error: String,
}

#[derive(Default)]
struct RenderedResults {
    lines: BoundedLines,
    counts: Counts,
}

impl<'de> Deserialize<'de> for RenderedResults {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ResultsVisitor;

        impl<'de> Visitor<'de> for ResultsVisitor {
            type Value = RenderedResults;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Trivy results array")
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                let mut rendered = RenderedResults::default();
                while rendered.lines.accepting() {
                    let Some(result) = seq.next_element::<ScanResult>()? else {
                        return Ok(rendered);
                    };
                    rendered.counts.merge(result.counts);
                    rendered.lines.append(result.lines);
                }
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    rendered.lines.truncate();
                    while seq.next_element::<IgnoredAny>()?.is_some() {}
                }
                Ok(rendered)
            }
        }

        deserializer.deserialize_seq(ResultsVisitor)
    }
}

struct ScanResult {
    lines: BoundedLines,
    counts: Counts,
}

#[derive(Deserialize)]
#[serde(field_identifier)]
enum ResultField {
    #[serde(rename = "Vulnerabilities")]
    Vulnerabilities,
    #[serde(rename = "Misconfigurations")]
    Misconfigurations,
    #[serde(rename = "Secrets")]
    Secrets,
    #[serde(other)]
    Other,
}

impl<'de> Deserialize<'de> for ScanResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ResultVisitor;

        impl<'de> Visitor<'de> for ResultVisitor {
            type Value = ScanResult;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Trivy result object")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut lines = BoundedLines::default();
                let mut counts = Counts::default();
                while let Some(field) = map.next_key()? {
                    match field {
                        ResultField::Vulnerabilities => {
                            map.next_value_seed(DetectionSeed {
                                kind: FindingKind::Vulnerability,
                                lines: &mut lines,
                                counts: &mut counts,
                            })?;
                        }
                        ResultField::Misconfigurations => {
                            map.next_value_seed(DetectionSeed {
                                kind: FindingKind::Misconfiguration,
                                lines: &mut lines,
                                counts: &mut counts,
                            })?;
                        }
                        ResultField::Secrets => {
                            map.next_value_seed(DetectionSeed {
                                kind: FindingKind::Secret,
                                lines: &mut lines,
                                counts: &mut counts,
                            })?;
                        }
                        ResultField::Other => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(ScanResult { lines, counts })
            }
        }

        deserializer.deserialize_map(ResultVisitor)
    }
}

struct DetectionSeed<'a> {
    kind: FindingKind,
    lines: &'a mut BoundedLines,
    counts: &'a mut Counts,
}

impl<'de> DeserializeSeed<'de> for DetectionSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct DetectionVisitor<'a> {
            kind: FindingKind,
            lines: &'a mut BoundedLines,
            counts: &'a mut Counts,
        }

        impl<'de> Visitor<'de> for DetectionVisitor<'_> {
            type Value = ();

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a Trivy detections array")
            }

            fn visit_seq<S>(self, mut seq: S) -> Result<Self::Value, S::Error>
            where
                S: SeqAccess<'de>,
            {
                while self.lines.accepting() {
                    match self.kind {
                        FindingKind::Vulnerability => {
                            let Some(item) = seq.next_element::<Vulnerability>()? else {
                                return Ok(());
                            };
                            self.counts.record(self.kind, item.severity);
                            render_vulnerability(self.lines, item);
                        }
                        FindingKind::Misconfiguration => {
                            let Some(item) = seq.next_element::<Misconfiguration>()? else {
                                return Ok(());
                            };
                            if !item.status.eq_ignore_ascii_case("PASS") {
                                self.counts.record(self.kind, item.severity);
                                render_misconfiguration(self.lines, item);
                            }
                        }
                        FindingKind::Secret => {
                            let Some(item) = seq.next_element::<Secret>()? else {
                                return Ok(());
                            };
                            self.counts.record(self.kind, item.severity);
                            render_secret(self.lines, item);
                        }
                    }
                }
                if seq.next_element::<IgnoredAny>()?.is_some() {
                    self.lines.truncate();
                    while seq.next_element::<IgnoredAny>()?.is_some() {}
                }
                Ok(())
            }
        }

        deserializer.deserialize_seq(DetectionVisitor {
            kind: self.kind,
            lines: self.lines,
            counts: self.counts,
        })
    }
}

#[derive(Deserialize)]
struct Vulnerability {
    #[serde(rename = "VulnerabilityID", default)]
    id: String,
    #[serde(rename = "PkgName", default)]
    package: String,
    #[serde(rename = "InstalledVersion", default)]
    installed: String,
    #[serde(rename = "FixedVersion", default)]
    fixed: String,
    #[serde(rename = "Title", default)]
    title: String,
    #[serde(rename = "Severity", default)]
    severity: Severity,
}

#[derive(Deserialize)]
struct Misconfiguration {
    #[serde(rename = "ID", default)]
    id: String,
    #[serde(rename = "Title", default)]
    title: String,
    #[serde(rename = "Message", default)]
    message: String,
    #[serde(rename = "Severity", default)]
    severity: Severity,
    #[serde(rename = "Status", default)]
    status: String,
}

#[derive(Deserialize)]
struct Secret {
    #[serde(rename = "RuleID", default)]
    id: String,
    #[serde(rename = "Title", default)]
    title: String,
    #[serde(rename = "Category", default)]
    category: String,
    #[serde(rename = "Severity", default)]
    severity: Severity,
}

fn render_vulnerability(lines: &mut BoundedLines, item: Vulnerability) {
    let mut line = format!("  [vulnerability] {} {}", item.severity.label(), item.id);
    if !item.package.is_empty() {
        let _ = write!(line, " · {}@{}", item.package, item.installed);
    }
    if !item.fixed.is_empty() {
        let _ = write!(line, " → {}", item.fixed);
    }
    if !item.title.is_empty() {
        let _ = write!(line, " — {}", item.title);
    }
    lines.push(line);
}

fn render_misconfiguration(lines: &mut BoundedLines, item: Misconfiguration) {
    let mut line = format!("  [misconfiguration] {} {}", item.severity.label(), item.id);
    if !item.title.is_empty() {
        let _ = write!(line, " — {}", item.title);
    } else if !item.message.is_empty() {
        let _ = write!(line, " — {}", item.message);
    }
    lines.push(line);
}

fn render_secret(lines: &mut BoundedLines, item: Secret) {
    let mut line = format!("  [secret] {} {}", item.severity.label(), item.id);
    if !item.title.is_empty() {
        let _ = write!(line, " — {}", item.title);
    } else if !item.category.is_empty() {
        let _ = write!(line, " — {}", item.category);
    }
    lines.push(line);
}

fn render_finding(rendered: &mut RenderedFindings, finding: Finding) {
    let mut counts = finding.results.counts;
    if !finding.error.is_empty() {
        counts.errors += 1;
    }
    if counts.findings() == 0 && counts.errors == 0 {
        return;
    }

    rendered.resources += 1;
    rendered.counts.merge(counts);
    if !rendered.lines.push_static("") {
        return;
    }
    let mut heading = String::new();
    if !finding.namespace.is_empty() {
        let _ = write!(heading, "{} · ", finding.namespace);
    }
    let _ = write!(heading, "{}/{}", finding.kind, finding.name);
    if !rendered.lines.push(heading) {
        return;
    }
    if !rendered.lines.push(format!(
        "  {} vulnerabilities · {} misconfigurations · {} secrets · C {} H {} M {} L {} U {}",
        counts.vulnerabilities,
        counts.misconfigurations,
        counts.secrets,
        counts.critical,
        counts.high,
        counts.medium,
        counts.low,
        counts.unknown
    )) {
        return;
    }
    rendered.lines.append(finding.results.lines);
    if !finding.error.is_empty() {
        rendered.lines.push_prefixed("  ERROR ", finding.error);
    }
}

fn parse_reader(
    reader: impl Read,
    requested_context: &str,
    requested_namespace: &str,
) -> Result<ReportView, String> {
    let envelope: Envelope =
        serde_json::from_reader(reader).map_err(|e| format!("invalid JSON from Trivy: {e}"))?;
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
    let findings = envelope.findings.counts.findings();
    let critical = envelope.findings.counts.critical;
    let high = envelope.findings.counts.high;
    let mut lines = BoundedLines::default();
    lines.push_static("Summary");
    if !envelope.cluster_name.is_empty() {
        lines.push_prefixed("  cluster:     ", envelope.cluster_name);
    }
    if !requested_context.is_empty() {
        lines.push(format!("  context:     {requested_context}"));
    }
    lines.push(format!(
        "  namespace:   {}",
        if requested_namespace.is_empty() {
            "all"
        } else {
            requested_namespace
        }
    ));
    lines.push(format!(
        "  resources:   {} affected",
        envelope.findings.resources
    ));
    lines.push(format!("  findings:    {findings}"));
    lines.push(format!(
        "  severity:    critical {} · high {} · medium {} · low {} · unknown {}",
        critical,
        high,
        envelope.findings.counts.medium,
        envelope.findings.counts.low,
        envelope.findings.counts.unknown
    ));
    lines.push(format!(
        "  categories:  vulnerabilities {} · misconfigurations {} · secrets {}",
        envelope.findings.counts.vulnerabilities,
        envelope.findings.counts.misconfigurations,
        envelope.findings.counts.secrets
    ));
    if envelope.findings.counts.errors > 0 {
        lines.push(format!(
            "  scan errors: {}",
            envelope.findings.counts.errors
        ));
    }
    lines.append(envelope.findings.lines);
    if envelope.findings.resources == 0 {
        lines.push_static("");
        lines.push_static("No security findings were returned.");
    }

    let truncated = lines.truncated;
    ReportView {
        title: if truncated {
            format!("trivy — {findings}+ findings")
        } else {
            format!("trivy — {findings} findings")
        },
        lines: lines.finish(),
        findings,
        critical,
        high,
        truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_uses_positional_context_and_namespace_flag() {
        let mut command = tokio::process::Command::new("trivy");
        configure_command(&mut command, "prod", "apps");
        let args = command.as_std().get_args().collect::<Vec<_>>();
        assert_eq!(
            args,
            [
                "kubernetes",
                "--format",
                "json",
                "--report",
                "summary",
                "--quiet",
                "--disable-telemetry",
                "--skip-version-check",
                "--no-progress",
                "--parallel",
                "1",
                "--list-all-pkgs=false",
                "--disable-node-collector",
                "--timeout",
                "5m",
                "--include-namespaces",
                "apps",
                "prod",
            ]
        );
        assert_eq!(args.last(), Some(&std::ffi::OsStr::new("prod")));
        assert!(!args.contains(&std::ffi::OsStr::new("--context")));

        let mut command = tokio::process::Command::new("trivy");
        configure_command(&mut command, "", "");
        assert!(
            !command
                .as_std()
                .get_args()
                .any(|arg| arg == "--include-namespaces")
        );
    }

    #[test]
    fn parses_and_formats_kubernetes_json() {
        let json = r#"{
            "SchemaVersion": 2,
            "ClusterName": "prod-cluster",
            "Findings": [{
                "Namespace": "apps",
                "Kind": "Deployment",
                "Name": "web",
                "Results": [{
                    "Target": "nginx:1.20",
                    "Vulnerabilities": [{
                        "VulnerabilityID": "CVE-2026-1234",
                        "PkgName": "openssl",
                        "InstalledVersion": "1.0",
                        "FixedVersion": "1.1",
                        "Title": "Example vulnerability",
                        "Severity": "CRITICAL"
                    }],
                    "Misconfigurations": [{
                        "ID": "AVD-KSV-0001",
                        "Title": "Runs as root",
                        "Severity": "HIGH",
                        "Status": "FAIL"
                    }],
                    "Secrets": [{
                        "RuleID": "generic-api-key",
                        "Title": "API key",
                        "Severity": "MEDIUM"
                    }]
                }]
            }]
        }"#;
        let view = parse_reader(json.as_bytes(), "prod", "apps").unwrap();
        assert_eq!(view.findings, 3);
        assert_eq!(view.critical, 1);
        assert_eq!(view.high, 1);
        assert!(!view.truncated);
        assert_eq!(view.title, "trivy — 3 findings");
        assert!(
            view.lines
                .iter()
                .any(|line| line == "apps · Deployment/web")
        );
        assert!(view.lines.iter().any(|line| line.contains("CVE-2026-1234")));
        assert!(view.lines.iter().any(|line| line.contains("AVD-KSV-0001")));
        assert!(
            view.lines
                .iter()
                .any(|line| line.contains("generic-api-key"))
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
    }

    #[test]
    fn malformed_json_is_actionable() {
        let error = parse_reader("not json".as_bytes(), "", "").err().unwrap();
        assert!(error.starts_with("invalid JSON from Trivy:"), "{error}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn scan_timeout_stops_a_hung_process() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "sofka-trivy-timeout-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let executable = root.join("trivy");
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
        assert!(error.starts_with("Trivy scan timed out"), "{error}");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn path_detection_requires_an_executable_and_honours_path_order() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "sofka-trivy-path-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let first = root.join("first");
        let second = root.join("second");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        std::fs::write(first.join("trivy"), "not executable").unwrap();
        let executable = second.join("trivy");
        std::fs::write(&executable, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = std::env::join_paths([&first, &second]).unwrap();
        assert_eq!(detect_in_path(&path), Some(executable));
        std::fs::remove_dir_all(root).unwrap();
    }
}
