//! Versioned external plugin packages and their bounded process/report protocol.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use serde::Deserialize;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::config::Plugin;

pub const MAX_BYTES: usize = 1 << 20;
pub const MAX_LINES: usize = 5_000;

#[derive(Debug, Clone, Deserialize)]
pub struct Input {
    /// Inline configuration ignores unknown fields. Package validation rejects them.
    #[serde(flatten)]
    unknown_fields: BTreeMap<String, toml::Value>,
    #[serde(rename = "type")]
    pub kind: String,
    pub default: Option<String>,
    pub min: Option<u64>,
    pub max: Option<u64>,
    #[serde(default)]
    pub choices: Vec<String>,
}

impl Input {
    fn validate(&self, value: &str) -> Result<(), String> {
        let number = match self.kind.as_str() {
            "string" => None,
            "boolean" if matches!(value, "true" | "false") => None,
            "integer" => Some(
                value
                    .parse::<u64>()
                    .map_err(|_| "expected unsigned integer")?,
            ),
            "duration" => Some(crate::providers::parse_lookback(value)? as u64),
            _ => return Err(format!("invalid {} value {value:?}", self.kind)),
        };
        if let Some(n) = number
            && (self.min.is_some_and(|m| n < m) || self.max.is_some_and(|m| n > m))
        {
            return Err(format!(
                "value outside range {:?}..{:?}",
                self.min, self.max
            ));
        }
        if !self.choices.is_empty() && !self.choices.iter().any(|c| c == value) {
            return Err(format!("expected one of {}", self.choices.join(", ")));
        }
        Ok(())
    }
}

pub fn inputs(plugin: &Plugin, arguments: &str) -> Result<BTreeMap<String, String>, String> {
    let mut supplied = BTreeMap::new();
    for word in arguments.split_whitespace() {
        let (name, value) = word
            .split_once('=')
            .ok_or("use name=value plugin arguments")?;
        if !plugin.inputs.contains_key(name) {
            return Err(format!("unknown input {name:?}"));
        }
        if supplied
            .insert(name.to_string(), value.to_string())
            .is_some()
        {
            return Err(format!("duplicate input {name:?}"));
        }
    }
    for (name, spec) in &plugin.inputs {
        let value = supplied
            .get(name)
            .or(spec.default.as_ref())
            .ok_or_else(|| format!("missing input {name}=…"))?
            .clone();
        spec.validate(&value).map_err(|e| format!("{name}: {e}"))?;
        supplied.insert(name.clone(), value);
    }
    Ok(supplied)
}

pub fn input_arg(value: &str, inputs: &BTreeMap<String, String>) -> String {
    value
        .strip_prefix("${input.")
        .and_then(|s| s.strip_suffix('}'))
        .and_then(|key| inputs.get(key))
        .cloned()
        .unwrap_or_else(|| value.into())
}

pub fn available(plugin: &Plugin) -> Result<(), String> {
    let missing: Vec<_> = plugin
        .requires
        .iter()
        .filter(|name| executable(name).is_none())
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "missing executables: {}{}",
            missing
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            plugin
                .install
                .as_ref()
                .map(|s| format!(" — {s}"))
                .unwrap_or_default()
        ))
    }
}

pub fn executable(name: &str) -> Option<PathBuf> {
    let candidates = if name.contains(std::path::MAIN_SEPARATOR) {
        vec![PathBuf::from(name)]
    } else {
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
            .map(|p| p.join(name))
            .collect()
    };
    candidates.into_iter().find(|p| {
        p.metadata().is_ok_and(|m| {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                m.is_file() && m.permissions().mode() & 0o111 != 0
            }
            #[cfg(not(unix))]
            {
                m.is_file()
            }
        })
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    plugin: Plugin,
}

pub fn read_package(dir: &Path) -> Result<Plugin, String> {
    let dir = dir.canonicalize().map_err(|e| e.to_string())?;
    let path = dir.join("plugin.toml");
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(&path)
        .map_err(|e| e.to_string())?
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > MAX_BYTES {
        return Err("manifest exceeds 1 MiB".into());
    }
    let mut plugin = parse_manifest(std::str::from_utf8(&bytes).map_err(|e| e.to_string())?)?;
    if plugin.command.starts_with("./") {
        let command = dir
            .join(&plugin.command)
            .canonicalize()
            .map_err(|e| e.to_string())?;
        if !command.starts_with(&dir) {
            return Err("relative command escapes package directory".into());
        }
        plugin.command = command.to_string_lossy().into_owned();
    }
    for requirement in &mut plugin.requires {
        if requirement.starts_with("./") {
            *requirement = dir.join(&*requirement).to_string_lossy().into_owned();
        }
    }
    if !plugin.requires.contains(&plugin.command) {
        plugin.requires.push(plugin.command.clone());
    }
    plugin.package_dir = Some(dir);
    Ok(plugin)
}

/// Parse and validate a `plugin.toml`, wherever it came from.
pub fn parse_manifest(text: &str) -> Result<Plugin, String> {
    let manifest: Manifest = toml::from_str(text).map_err(|e| e.to_string())?;
    if manifest.schema_version != 1 {
        return Err("unsupported schema_version (expected 1)".into());
    }
    validate_plugin(&manifest.plugin)?;
    Ok(manifest.plugin)
}

/// The manifest of every package sofka ships. Kept as real files under
/// `plugins/` so `--validate-plugin` covers them like any other package.
const BUNDLED: &[(&str, &str)] = &[("sanitize", include_str!("../plugins/sanitize/plugin.toml"))];

/// The packages sofka ships, with `command` pointed at the running executable.
/// The adapters live in this binary, so a normal install has nothing to copy
/// and needs no extra language runtime on PATH.
pub fn bundled() -> Vec<Result<Plugin, String>> {
    let exe = std::env::current_exe();
    BUNDLED
        .iter()
        .map(|(name, text)| {
            let mut plugin = parse_manifest(text).map_err(|e| format!("bundled {name}: {e}"))?;
            let exe = exe
                .as_ref()
                .map_err(|e| format!("bundled {name}: locating the sofka binary: {e}"))?;
            plugin.command = exe.to_string_lossy().into_owned();
            plugin.requires = vec![plugin.command.clone()];
            plugin.bundled = true;
            Ok(plugin)
        })
        .collect()
}

pub fn validate_plugin(plugin: &Plugin) -> Result<(), String> {
    if let Some(field) = plugin.unknown_fields.keys().next() {
        return Err(format!("unknown field {field:?} in plugin manifest"));
    }
    if plugin.name.trim().is_empty() || plugin.command.trim().is_empty() {
        return Err("name and command must not be empty".into());
    }
    if let Some(name) = &plugin.palette
        && (name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
    {
        return Err("palette must contain lowercase letters, digits or hyphens".into());
    }
    if plugin
        .palette
        .as_deref()
        .is_some_and(crate::app::plugin_command_reserved)
    {
        return Err("palette command is reserved by sofka".into());
    }
    let warnings = crate::config::plugin_warnings(std::slice::from_ref(plugin));
    if !warnings.is_empty() {
        return Err(warnings.join("; "));
    }
    if !matches!(
        plugin.target.as_deref(),
        None | Some("selection" | "context")
    ) {
        return Err("target must be selection or context".into());
    }
    if plugin.port_forward.is_some()
        && (plugin.target.as_deref() == Some("context")
            || plugin.output.as_deref() != Some("report"))
    {
        return Err("port_forward requires target = selection and output = report".into());
    }
    if !matches!(
        plugin.output.as_deref(),
        Some("popup" | "background" | "report")
    ) {
        return Err("packages require captured output: popup, background or report".into());
    }
    if plugin.shell {
        return Err("packages must use an executable adapter, not shell = true".into());
    }
    for (name, spec) in &plugin.inputs {
        if let Some(field) = spec.unknown_fields.keys().next() {
            return Err(format!("unknown field {field:?} in plugin input {name:?}"));
        }
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(format!("invalid input name {name:?}"));
        }
        if !matches!(
            spec.kind.as_str(),
            "string" | "integer" | "boolean" | "duration"
        ) {
            return Err(format!("{name}: unsupported input type"));
        }
        if spec.min.zip(spec.max).is_some_and(|(min, max)| min > max) {
            return Err(format!("{name}: min exceeds max"));
        }
        if (spec.min.is_some() || spec.max.is_some())
            && !matches!(spec.kind.as_str(), "integer" | "duration")
        {
            return Err(format!("{name}: min/max require integer or duration"));
        }
        if let Some(value) = &spec.default {
            spec.validate(value).map_err(|e| format!("{name}: {e}"))?;
        }
    }
    for argument in plugin.args.iter().chain(plugin.port_forward.iter()) {
        if argument.contains("${input.") {
            let name = argument.strip_prefix("${input.").and_then(|a| a.strip_suffix('}'))
                .filter(|name| plugin.inputs.contains_key(*name))
                .ok_or_else(|| format!("invalid input placeholder {argument:?}; use a declared input as a whole argument"))?;
            if name.is_empty() {
                return Err("empty input placeholder".into());
            }
        }
    }
    Ok(())
}

pub fn load_packages(dir: &Path, plugins: &mut Vec<Plugin>, warnings: &mut Vec<String>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
        Err(e) => {
            warnings.push(format!("{}: {e}", dir.display()));
            return;
        }
    };
    let mut paths = Vec::new();
    for entry in entries {
        match entry {
            Ok(e) if e.path().is_dir() => paths.push(e.path()),
            Ok(_) => {}
            Err(e) => warnings.push(format!("{}: {e}", dir.display())),
        }
    }
    paths.sort();
    for path in paths {
        match read_package(&path) {
            Ok(p) => {
                if plugins.iter().any(|old| {
                    old.name == p.name || (p.palette.is_some() && old.palette == p.palette)
                }) {
                    warnings.push(format!(
                        "{}: duplicate plugin name/command; earlier configuration wins",
                        path.display()
                    ));
                } else {
                    if let Err(e) = available(&p) {
                        warnings.push(format!("plugin {}: {e}", p.name));
                    }
                    plugins.push(p);
                }
            }
            Err(e) => warnings.push(format!("ignoring {}: {e}", path.display())),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    schema_version: u32,
    title: String,
    #[serde(default)]
    sections: Vec<Section>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Section {
    title: String,
    #[serde(default)]
    lines: Vec<String>,
    #[serde(default)]
    columns: Vec<String>,
    #[serde(default)]
    rows: Vec<Vec<String>>,
}

pub fn render_report(bytes: &[u8]) -> Result<Vec<String>, String> {
    if bytes.len() > MAX_BYTES {
        return Err("report exceeds 1 MiB".into());
    }
    let report: Report =
        serde_json::from_slice(bytes).map_err(|e| format!("invalid plugin report: {e}"))?;
    if report.schema_version != 1 {
        return Err("unsupported report schema_version (expected 1)".into());
    }
    let mut lines = vec![clean(&report.title)];
    for section in report.sections {
        lines.push(String::new());
        lines.push(clean(&section.title));
        lines.extend(section.lines.iter().map(|s| clean(s)));
        if !section.columns.is_empty() {
            lines.push(
                section
                    .columns
                    .iter()
                    .map(|s| clean(s))
                    .collect::<Vec<_>>()
                    .join(" | "),
            );
        }
        for row in section.rows {
            if row.len() != section.columns.len() {
                return Err("report row length does not match columns".into());
            }
            lines.push(row.iter().map(|s| clean(s)).collect::<Vec<_>>().join(" | "));
        }
    }
    Ok(bound_lines(lines))
}

fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

#[derive(Default)]
pub struct Lines {
    lines: Vec<String>,
    bytes: usize,
    truncated: bool,
}

impl Lines {
    pub fn push(&mut self, line: String) {
        if self.truncated {
            return;
        }
        if self.lines.len() >= MAX_LINES || self.bytes + line.len() > MAX_BYTES {
            self.truncated = true;
        } else {
            self.bytes += line.len();
            self.lines.push(line);
        }
    }

    pub fn extend(&mut self, lines: impl IntoIterator<Item = String>) {
        for line in lines {
            self.push(line);
        }
    }

    pub fn finish(mut self) -> Vec<String> {
        if self.truncated {
            self.lines.push("… output truncated".into());
        }
        self.lines
    }
}

pub fn bound_lines(lines: Vec<String>) -> Vec<String> {
    let mut output = Lines::default();
    output.extend(lines);
    output.finish()
}

pub struct Job {
    pub label: String,
    pub argv: Vec<String>,
    pub directory: Option<PathBuf>,
    pub request: Option<Value>,
    pub object: Option<std::sync::Arc<kube::core::DynamicObject>>,
    pub forward: Option<Forward>,
}

pub struct Forward {
    pub argv: Vec<String>,
    pub remote: u16,
    pub local: Option<u16>,
}

/// Dropping an owner cancels its task instead of detaching it.
pub struct Task(pub tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Process {
    child: tokio::process::Child,
    #[cfg(unix)]
    group: u32,
}
impl Process {
    fn spawn(command: &mut tokio::process::Command) -> std::io::Result<Self> {
        command.kill_on_drop(true);
        #[cfg(unix)]
        command.process_group(0);
        let child = command.spawn()?;
        Ok(Self {
            #[cfg(unix)]
            group: child.id().unwrap_or_default(),
            child,
        })
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        // Adapters may launch scanners; cancel the whole private process group.
        #[cfg(unix)]
        if self.group > 0 {
            let _ = std::process::Command::new("/bin/kill")
                .args(["-KILL", "--", &format!("-{}", self.group)])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = self.child.start_kill();
    }
}

async fn read_limited(mut stream: impl AsyncRead + Unpin) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    (&mut stream)
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > MAX_BYTES {
        return Err(std::io::Error::other("plugin output exceeds 1 MiB"));
    }
    Ok(bytes)
}

async fn forward(spec: &Forward) -> std::io::Result<(u16, Option<(Process, Task)>)> {
    if let Some(port) = spec.local {
        return Ok((port, None));
    }
    use tokio::io::{AsyncBufReadExt, BufReader};
    let mut cmd = tokio::process::Command::new(&spec.argv[0]);
    cmd.args(&spec.argv[1..])
        .arg(format!(":{}", spec.remote))
        .arg("--address=127.0.0.1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = Process::spawn(&mut cmd)?;
    let mut stdout = BufReader::new(child.child.stdout.take().unwrap());
    let mut line = Vec::new();
    loop {
        let n = (&mut stdout)
            .take(4096)
            .read_until(b'\n', &mut line)
            .await?;
        if n == 0 || line.len() >= 4096 {
            return Err(std::io::Error::other(
                "port-forward failed before becoming ready",
            ));
        }
        let text = String::from_utf8_lossy(&line);
        if let Some(port) = text
            .strip_prefix("Forwarding from 127.0.0.1:")
            .and_then(|s| s.split_whitespace().next())
            .and_then(|p| p.parse().ok())
        {
            let drain = Task(tokio::spawn(async move {
                let _ = tokio::io::copy(&mut stdout, &mut tokio::io::sink()).await;
            }));
            return Ok((port, Some((child, drain))));
        }
        line.clear();
    }
}

struct RequestBuffer(Vec<u8>);

impl std::io::Write for RequestBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if self.0.len() + bytes.len() > MAX_BYTES {
            return Err(std::io::Error::other("plugin request exceeds 1 MiB"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub async fn execute(mut job: Job) -> std::io::Result<std::process::Output> {
    let mut forward_owner = None;
    if let Some(spec) = &job.forward {
        let (port, owner) = forward(spec).await?;
        forward_owner = owner;
        if let Some(request) = &mut job.request {
            request["forward"] = serde_json::json!({"host": "127.0.0.1", "local_port": port, "remote_port": spec.remote});
        }
    }
    let input = job
        .request
        .as_ref()
        .map(|request| {
            let mut writer = RequestBuffer(Vec::new());
            if let Some(object) = &job.object {
                #[derive(serde::Serialize)]
                struct Request<'a> {
                    #[serde(flatten)]
                    fields: &'a Value,
                    object: &'a kube::core::DynamicObject,
                }
                serde_json::to_writer(
                    &mut writer,
                    &Request {
                        fields: request,
                        object,
                    },
                )?;
            } else {
                serde_json::to_writer(&mut writer, request)?;
            }
            Ok::<_, std::io::Error>(writer.0)
        })
        .transpose()?;
    let mut command = tokio::process::Command::new(&job.argv[0]);
    command
        .args(&job.argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(dir) = &job.directory {
        command.current_dir(dir);
    }
    let mut process = Process::spawn(&mut command)?;
    let mut stdin = process.child.stdin.take().unwrap();
    let stdout = process.child.stdout.take().unwrap();
    let stderr = process.child.stderr.take().unwrap();

    let write = async {
        if let Some(input) = input {
            stdin.write_all(&input).await?;
        }
        drop(stdin);
        Ok::<_, std::io::Error>(())
    };
    let (_, stdout, stderr, status) = tokio::try_join!(
        write,
        read_limited(stdout),
        read_limited(stderr),
        process.child.wait()
    )?;
    drop(forward_owner);
    Ok(std::process::Output {
        status,
        stdout,
        stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(command: &str, args: &[&str]) -> Job {
        Job {
            label: "test".into(),
            argv: std::iter::once(command)
                .chain(args.iter().copied())
                .map(str::to_string)
                .collect(),
            directory: None,
            request: None,
            object: None,
            forward: None,
        }
    }

    fn package(text: &str) -> Result<Plugin, String> {
        let dir = std::env::temp_dir().join(format!(
            "sofka-package-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("plugin.toml"), text).unwrap();
        let result = read_package(&dir);
        std::fs::remove_dir_all(dir).unwrap();
        result
    }

    #[test]
    fn manifests_reject_unknown_versions_fields_commands_and_invalid_inputs() {
        let valid = "schema_version = 1\n[plugin]\nname = 'Demo'\npalette = 'demo'\ncommand = '/bin/cat'\noutput = 'report'\n";
        assert!(package(valid).is_ok());
        assert!(
            package(&valid.replace("schema_version = 1", "schema_version = 2"))
                .unwrap_err()
                .contains("unsupported")
        );
        assert!(
            package(&format!("{valid}typo = true\n"))
                .unwrap_err()
                .contains("unknown field")
        );
        let nested_error = package(&format!(
            "{valid}[plugin.inputs.count]\ntype = 'integer'\ndefault = '2'\nobsolete_option = true\n"
        ))
        .unwrap_err();
        assert!(nested_error.contains("unknown field \"obsolete_option\""));
        assert!(nested_error.contains("plugin input \"count\""));
        assert!(
            package(&valid.replace("palette = 'demo'", "palette = 'ctx'"))
                .unwrap_err()
                .contains("reserved")
        );
        assert!(
            package(&valid.replace("output = 'report'", "output = 'terminal'"))
                .unwrap_err()
                .contains("captured output")
        );
        assert!(
            package(&format!(
                "{valid}[plugin.inputs.count]\ntype = 'integer'\ndefault = '99'\nmax = 5\n"
            ))
            .unwrap_err()
            .contains("outside range")
        );
        assert!(
            package(&format!("{valid}args = ['${{input.missing}}']\n"))
                .unwrap_err()
                .contains("invalid input placeholder")
        );
    }

    #[test]
    fn report_rejects_wrong_row_shapes_and_bounds_rendered_lines() {
        let bad = br#"{"schema_version":1,"title":"Scan","sections":[{"title":"Rows","columns":["One"],"rows":[["a","b"]]}]}"#;
        assert!(render_report(bad).unwrap_err().contains("row length"));
        let report = serde_json::json!({"schema_version": 1, "title": "Scan", "sections": [{"title": "Rows", "lines": vec!["test"; MAX_LINES + 1]}]});
        let lines = render_report(&serde_json::to_vec(&report).unwrap()).unwrap();
        assert!(lines.len() <= MAX_LINES + 1);
        assert!(lines.last().unwrap().contains("truncated"));
        assert!(
            render_report(&vec![b' '; MAX_BYTES + 1])
                .unwrap_err()
                .contains("exceeds")
        );
    }

    #[test]
    fn aggregate_output_budget_applies_across_jobs() {
        let mut lines = Lines::default();
        for _ in 0..100 {
            lines.push("x".repeat(50_000));
        }
        let output = lines.finish();
        assert!(output.iter().map(String::len).sum::<usize>() <= MAX_BYTES + 32);
        assert!(output.last().unwrap().contains("truncated"));
    }

    #[tokio::test]
    async fn capture_stops_chatty_processes_before_unbounded_allocation() {
        let error = execute(job("/bin/sh", &["-c", "head -c 1100000 /dev/zero"]))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("exceeds 1 MiB"));
    }

    #[tokio::test]
    async fn adapters_receive_stdin_and_run_in_their_package_directory() {
        let mut command = job("/bin/sh", &["-c", "pwd; cat"]);
        let dir = std::env::temp_dir().canonicalize().unwrap();
        command.directory = Some(dir.clone());
        command.request =
            Some(serde_json::json!({"schema_version":1,"object":{"metadata":{"name":"pod"}}}));
        let output = execute(command).await.unwrap();
        assert!(output.status.success());
        let text = String::from_utf8(output.stdout).unwrap();
        let (cwd, json) = text.split_once('\n').unwrap();
        assert_eq!(Path::new(cwd), dir);
        assert_eq!(
            serde_json::from_str::<Value>(json).unwrap()["object"]["metadata"]["name"],
            "pod"
        );
    }

    #[tokio::test]
    async fn managed_forward_waits_for_readiness_and_supplies_local_port() {
        let mut command = job("/bin/cat", &[]);
        command.request = Some(serde_json::json!({"schema_version":1}));
        command.forward = Some(Forward {
            argv: vec![
                "/bin/sh".into(),
                "-c".into(),
                "printf 'Forwarding from 127.0.0.1:32123 -> 80\\n'; sleep 30".into(),
                "forward".into(),
            ],
            remote: 80,
            local: None,
        });
        let output = tokio::time::timeout(std::time::Duration::from_secs(3), execute(command))
            .await
            .unwrap()
            .unwrap();
        assert!(output.status.success());
        let request: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(request["forward"]["local_port"], 32123);
        assert_eq!(request["forward"]["remote_port"], 80);
    }

    #[tokio::test]
    async fn existing_forward_does_not_spawn_another_process() {
        let mut command = job("/bin/cat", &[]);
        command.request = Some(serde_json::json!({}));
        command.forward = Some(Forward {
            argv: vec!["does-not-exist".into()],
            remote: 443,
            local: Some(32124),
        });
        let output = execute(command).await.unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap()["forward"]["local_port"],
            32124
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn timeout_kills_adapter_descendants() {
        let dir = std::env::temp_dir().join(format!("sofka-plugin-cancel-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let marker = dir.join("orphan");
        let command = job(
            "/bin/sh",
            &[
                "-c",
                "(sleep 1; printf orphan > \"$1\") & wait",
                "test",
                marker.to_str().unwrap(),
            ],
        );
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(150), execute(command))
                .await
                .is_err()
        );
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        assert!(!marker.exists(), "a descendant survived cancellation");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
