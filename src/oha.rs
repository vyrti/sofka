//! Optional oha CLI discovery, HTTP benchmark execution, and report parsing.
//!
//! Unlike the cluster-wide scanners, a load generator needs one reachable URL.
//! The selected object supplies an address when it advertises one (an ingress
//! host, a load-balancer address, a cluster IP that happens to be routable);
//! sofka probes that address first and only falls back to a `kubectl
//! port-forward` when nothing answers, so the common on-VPN case pays no
//! forwarding cost at all.

use std::ffi::OsStr;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt};

const EXECUTABLE: &str = "oha";
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

/// Longest run `:oha` will ask for. A load generator pointed at a live cluster
/// is the one optional command that can do harm, so the ceiling is enforced
/// before the process starts rather than trusted to the user's argument.
pub const MAX_DURATION: Duration = Duration::from_secs(5 * 60);
const DEFAULT_DURATION: Duration = Duration::from_secs(10);
const DEFAULT_CONNECTIONS: u32 = 20;
const MAX_CONNECTIONS: u32 = 200_000;
/// Head-room over the requested duration for DNS, connection setup, the
/// optional forward, and oha's own reporting.
const RUN_SLACK: Duration = Duration::from_secs(30);
/// A direct address either answers quickly or is not routable from here.
const PROBE_TIMEOUT: Duration = Duration::from_millis(1_500);
const FORWARD_READY_TIMEOUT: Duration = Duration::from_secs(5);
const FORWARD_POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Distribution maps are remote input; cap the rendered rows.
const MAX_DISTRIBUTION_ROWS: usize = 64;
/// Column the report's values line up on.
const FIELD_COLUMN: usize = 13;

/// A report already reduced to what the document view needs.
#[derive(Debug)]
pub struct ReportView {
    pub title: String,
    pub lines: Vec<String>,
    pub requests: u64,
    pub success_rate: f64,
    pub requests_per_sec: f64,
    pub truncated: bool,
}

/// Find oha on the process PATH.
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

/// How hard to push, from `:oha [duration] [connections]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Options {
    pub duration: Duration,
    pub connections: u32,
    /// Which declared port to benchmark. `None` picks one (see [`choose_port`]).
    pub port: Option<u16>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            duration: DEFAULT_DURATION,
            connections: DEFAULT_CONNECTIONS,
            port: None,
        }
    }
}

impl Options {
    /// Hard deadline for the whole task, including any forward setup.
    fn deadline(&self) -> Duration {
        self.duration.saturating_add(RUN_SLACK)
    }
}

/// Parse `:oha [duration] [connections]`. Both are optional and positional;
/// every failure is reported before a process is spawned.
pub fn parse_options(args: &str) -> Result<Options, String> {
    let mut options = Options::default();
    // `port=` is named rather than positional so it can be given alone, and
    // so a bare number is never ambiguous between a duration and a port.
    let mut positional = Vec::new();
    for token in args.split_whitespace() {
        match token.strip_prefix("port=") {
            Some(raw) => options.port = Some(parse_port(raw)?),
            None => positional.push(token),
        }
    }
    let mut positional = positional.into_iter();
    if let Some(raw) = positional.next() {
        options.duration = parse_duration(raw)?;
    }
    if let Some(raw) = positional.next() {
        options.connections = parse_connections(raw)?;
    }
    if let Some(extra) = positional.next() {
        return Err(format!(
            "unexpected argument '{extra}' — usage: :oha [duration] [connections] [port=N]"
        ));
    }
    Ok(options)
}

fn parse_port(raw: &str) -> Result<u16, String> {
    raw.parse()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| format!("invalid port '{raw}'"))
}

fn parse_duration(raw: &str) -> Result<Duration, String> {
    let (value, scale) = match raw.strip_suffix('s') {
        Some(value) => (value, 1),
        None => match raw.strip_suffix('m') {
            Some(value) => (value, 60),
            None => (raw, 1),
        },
    };
    let parsed: u64 = value
        .parse()
        .map_err(|_| format!("invalid duration '{raw}' — try 10s or 2m"))?;
    let duration = Duration::from_secs(parsed.saturating_mul(scale));
    if duration.is_zero() {
        return Err("duration must be greater than zero".into());
    }
    if duration > MAX_DURATION {
        return Err(format!(
            "duration above the {}s cap",
            MAX_DURATION.as_secs()
        ));
    }
    Ok(duration)
}

fn parse_connections(raw: &str) -> Result<u32, String> {
    let parsed: u32 = raw
        .parse()
        .map_err(|_| format!("invalid connection count '{raw}'"))?;
    if parsed == 0 {
        return Err("connections must be greater than zero".into());
    }
    if parsed > MAX_CONNECTIONS {
        return Err(format!("connections above the {MAX_CONNECTIONS} cap"));
    }
    Ok(parsed)
}

/// One HTTP endpoint to benchmark.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub scheme: &'static str,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Target {
    pub fn url(&self) -> String {
        // A literal IPv6 address has to be bracketed for the authority to parse.
        if self.host.contains(':') {
            format!(
                "{}://[{}]:{}{}",
                self.scheme, self.host, self.port, self.path
            )
        } else {
            format!("{}://{}:{}{}", self.scheme, self.host, self.port, self.path)
        }
    }
}

/// `kubectl port-forward` fallback for an address that did not answer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForwardSpec {
    /// Positional `kubectl port-forward` target, e.g. `svc/web`.
    pub arg: String,
    pub remote_port: u16,
    pub scheme: &'static str,
    pub path: String,
}

impl ForwardSpec {
    fn local_target(&self, port: u16) -> Target {
        Target {
            scheme: self.scheme,
            host: "127.0.0.1".into(),
            port,
            path: self.path.clone(),
        }
    }
}

/// What to try, in order, for the selected object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub direct: Option<Target>,
    pub forward: Option<ForwardSpec>,
}

/// Which address actually served the run, for the report header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    Direct,
    ExistingForward,
    TemporaryForward,
}

impl Route {
    fn label(self) -> &'static str {
        match self {
            Route::Direct => "direct",
            Route::ExistingForward => "existing port-forward",
            Route::TemporaryForward => "temporary port-forward",
        }
    }
}

/// Resolve what to benchmark for the selected object. Returns the address the
/// object advertises (if any) plus the forward that can reach it regardless.
pub fn plan(
    kind_plural: &str,
    name: &str,
    data: &Value,
    port: Option<u16>,
) -> Result<Plan, String> {
    match kind_plural {
        "ingresses" => ingress_plan(data, port),
        "services" => service_plan(name, data, port),
        "pods" => pod_plan(name, data, port),
        _ => Err("benchmark applies to ingresses/services/pods".into()),
    }
}

/// Read a port number out of one `ports[]` entry.
fn port_number(spec: &Value, key: &str) -> Option<u16> {
    spec.get(key)
        .and_then(Value::as_i64)
        .and_then(|port| u16::try_from(port).ok())
}

/// Protocols that are definitely not an HTTP endpoint worth benchmarking.
const NON_HTTP_PROTOCOLS: &[&str] = &[
    "grpc",
    "tcp",
    "udp",
    "sctp",
    "tls",
    "redis",
    "postgres",
    "postgresql",
    "mysql",
    "mssql",
    "mongodb",
    "amqp",
    "kafka",
    "memcached",
    "ldap",
    "smtp",
    "dns",
];
/// Ports conventionally used to serve HTTP when nothing else says so.
const WELL_KNOWN_HTTP_PORTS: &[u16] = &[80, 443, 3000, 8000, 8008, 8080, 8443];

/// What a port says it speaks, preferring the explicit field over the name.
fn protocol_hint(spec: &Value) -> &str {
    spec.get("appProtocol")
        .and_then(Value::as_str)
        .or_else(|| spec.get("name").and_then(Value::as_str))
        .unwrap_or_default()
}

/// Kubernetes and Istio name ports by protocol with an optional suffix —
/// `http-web`, `grpc-api` — so the prefix carries as much signal as the bare
/// name, and matching only the bare name misses the common spelling.
fn speaks(hint: &str, protocols: &[&str]) -> bool {
    protocols.iter().any(|protocol| {
        hint.eq_ignore_ascii_case(protocol)
            || hint
                .split_once('-')
                .is_some_and(|(head, _)| head.eq_ignore_ascii_case(protocol))
    })
}

/// How likely this port is to be the HTTP endpoint. Ranked rather than
/// boolean: a port that says nothing still beats one that says `grpc`, and a
/// conventional HTTP port number beats one that says nothing at all. No
/// ranking can be complete, which is what `port=N` is for.
fn http_affinity(spec: &Value, key: &str) -> u8 {
    let hint = protocol_hint(spec);
    if speaks(hint, &["http", "https"]) {
        3
    } else if speaks(hint, NON_HTTP_PROTOCOLS) {
        0
    } else if port_number(spec, key).is_some_and(|p| WELL_KNOWN_HTTP_PORTS.contains(&p)) {
        2
    } else {
        1
    }
}

/// Choose the port to benchmark. An explicit `port=N` wins and must exist, so
/// a typo fails loudly instead of forwarding to nothing. Otherwise take the
/// highest [`http_affinity`], earliest declaration breaking a tie — a TCP
/// probe cannot tell a wrong choice from a right one, so the choice has to be
/// made from what the object declares.
fn choose_port<'a>(ports: &'a [Value], key: &str, wanted: Option<u16>) -> Option<&'a Value> {
    match wanted {
        Some(wanted) => ports.iter().find(|p| port_number(p, key) == Some(wanted)),
        None => ports
            .iter()
            .enumerate()
            .max_by_key(|(index, port)| (http_affinity(port, key), std::cmp::Reverse(*index)))
            .map(|(_, port)| port),
    }
}

/// The declared ports of `data` at `pointer`, as a slice.
fn declared_ports<'a>(data: &'a Value, pointer: &str) -> &'a [Value] {
    data.pointer(pointer)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default()
}

fn ingress_plan(data: &Value, port: Option<u16>) -> Result<Plan, String> {
    let rule = data.pointer("/spec/rules/0");
    let host = rule
        .and_then(|r| r.get("host"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| load_balancer_host(data))
        .ok_or("ingress advertises no host or address")?;
    let path = rule
        .and_then(|r| r.pointer("/http/paths/0/path"))
        .and_then(Value::as_str)
        .unwrap_or("/");
    let secure = ingress_is_tls(data, &host);
    Ok(Plan {
        direct: Some(Target {
            scheme: if secure { "https" } else { "http" },
            host,
            port: port.unwrap_or(if secure { 443 } else { 80 }),
            path: normalize_path(path),
        }),
        // An ingress is fronted by a controller, not by one forwardable pod.
        forward: None,
    })
}

/// TLS covers the host when a `spec.tls` entry lists it, or lists no hosts at
/// all (the catch-all form).
fn ingress_is_tls(data: &Value, host: &str) -> bool {
    let Some(tls) = data.pointer("/spec/tls").and_then(Value::as_array) else {
        return false;
    };
    tls.iter().any(|entry| match entry.get("hosts") {
        Some(Value::Array(hosts)) if !hosts.is_empty() => hosts
            .iter()
            .filter_map(Value::as_str)
            .any(|h| tls_host_matches(h, host)),
        _ => true,
    })
}

/// Certificate hosts may be wildcards: `*.example.com` covers `api.example.com`
/// but not `example.com` itself, and never a deeper label.
fn tls_host_matches(pattern: &str, host: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(suffix) => host
            .split_once('.')
            .is_some_and(|(_, rest)| rest.eq_ignore_ascii_case(suffix)),
        None => pattern.eq_ignore_ascii_case(host),
    }
}

fn load_balancer_host(data: &Value) -> Option<String> {
    let entry = data.pointer("/status/loadBalancer/ingress/0")?;
    entry
        .get("hostname")
        .and_then(Value::as_str)
        .or_else(|| entry.get("ip").and_then(Value::as_str))
        .filter(|host| !host.is_empty())
        .map(str::to_owned)
}

fn service_plan(name: &str, data: &Value, wanted: Option<u16>) -> Result<Plan, String> {
    let ports = declared_ports(data, "/spec/ports");
    if ports.is_empty() {
        return Err("service exposes no ports".into());
    }
    let spec_port = choose_port(ports, "port", wanted).ok_or_else(|| {
        format!(
            "port {} is not declared by this service",
            wanted.unwrap_or_default()
        )
    })?;
    let port = port_number(spec_port, "port").ok_or("service port is not a valid port number")?;
    let scheme = port_scheme(port, spec_port);
    let path = "/".to_string();
    // A load-balancer address is externally routable; a cluster IP may be too
    // (in-cluster, VPN, or a routed CNI), so it is still worth probing. A
    // headless service has no address of its own at all.
    let direct_host = load_balancer_host(data).or_else(|| {
        data.pointer("/spec/clusterIP")
            .and_then(Value::as_str)
            .filter(|ip| !ip.is_empty() && *ip != "None")
            .map(str::to_owned)
    });
    Ok(Plan {
        direct: direct_host.map(|host| Target {
            scheme,
            host,
            port,
            path: path.clone(),
        }),
        forward: Some(ForwardSpec {
            arg: format!("svc/{name}"),
            remote_port: port,
            scheme,
            path,
        }),
    })
}

fn pod_plan(name: &str, data: &Value, wanted: Option<u16>) -> Result<Plan, String> {
    // Every container's ports are candidates, not just the first container's.
    let ports: Vec<Value> = declared_ports(data, "/spec/containers")
        .iter()
        .flat_map(|c| declared_ports(c, "/ports"))
        .cloned()
        .collect();
    if ports.is_empty() {
        return Err("pod declares no container ports".into());
    }
    let container_port = choose_port(&ports, "containerPort", wanted).ok_or_else(|| {
        format!(
            "port {} is not declared by this pod",
            wanted.unwrap_or_default()
        )
    })?;
    let port = port_number(container_port, "containerPort")
        .ok_or("container port is not a valid port number")?;
    let scheme = port_scheme(port, container_port);
    let path = "/".to_string();
    Ok(Plan {
        direct: data
            .pointer("/status/podIP")
            .and_then(Value::as_str)
            .filter(|ip| !ip.is_empty())
            .map(|ip| Target {
                scheme,
                host: ip.to_string(),
                port,
                path: path.clone(),
            }),
        forward: Some(ForwardSpec {
            arg: format!("pod/{name}"),
            remote_port: port,
            scheme,
            path,
        }),
    })
}

/// `appProtocol` is the declared answer; the conventional port name and the
/// well-known port are the fallbacks.
fn port_scheme(port: u16, spec: &Value) -> &'static str {
    if speaks(protocol_hint(spec), &["https"]) || port == 443 || port == 8443 {
        "https"
    } else {
        "http"
    }
}

fn normalize_path(path: &str) -> String {
    // Ingress paths may be regexes when the class supports them; anything that
    // is not a plain prefix is not a URL we can request, so fall back to root.
    if path.is_empty() || !path.starts_with('/') || path.contains(['*', '(', ')', '?']) {
        "/".into()
    } else {
        path.to_string()
    }
}

/// Everything the background task needs; assembled on the app thread so the
/// task itself borrows nothing.
pub struct Launch {
    pub executable: PathBuf,
    pub plan: Plan,
    pub options: Options,
    /// Local port of a forward sofka already runs for this target, if any.
    pub existing_local_port: Option<u16>,
    /// argv prefix for a temporary forward, e.g.
    /// `["kubectl", "--context", "prod", "port-forward", "-n", "apps"]`.
    pub forward_argv: Vec<String>,
}

/// Benchmark the selected object, preferring an address that already answers.
pub async fn run(launch: Launch) -> Result<ReportView, String> {
    let timeout = launch.options.deadline();
    run_with_timeout(launch, timeout).await
}

pub(crate) async fn run_with_timeout(
    launch: Launch,
    timeout: Duration,
) -> Result<ReportView, String> {
    tokio::time::timeout(timeout, run_inner(launch))
        .await
        .map_err(|_| format!("oha run timed out after {} seconds", timeout.as_secs()))?
}

async fn run_inner(launch: Launch) -> Result<ReportView, String> {
    let Launch {
        executable,
        plan,
        options,
        existing_local_port,
        forward_argv,
    } = launch;

    // 1. The address the object advertises. On a VPN or in-cluster this is
    //    already routable, and forwarding would only add a hop.
    if let Some(target) = plan.direct.as_ref()
        && reachable(&target.host, target.port, PROBE_TIMEOUT).await
    {
        return execute(&executable, target, options, Route::Direct, None).await;
    }

    let Some(forward) = plan.forward else {
        let unreachable = plan
            .direct
            .map(|t| t.url())
            .unwrap_or_else(|| "the selection".into());
        return Err(format!("{unreachable} is not reachable from here"));
    };

    // 2. A forward the user already started with `f` — reuse it rather than
    //    opening a second one to the same target.
    if let Some(port) = existing_local_port {
        let target = forward.local_target(port);
        if reachable(&target.host, target.port, PROBE_TIMEOUT).await {
            return execute(&executable, &target, options, Route::ExistingForward, None).await;
        }
    }

    // 3. Our own forward, killed on drop when this task ends or is aborted.
    let (child, port) = start_forward(&forward_argv, &forward).await?;
    let target = forward.local_target(port);
    execute(
        &executable,
        &target,
        options,
        Route::TemporaryForward,
        Some(child),
    )
    .await
}

/// Whether anything accepts a TCP connection at `host:port` right now.
async fn reachable(host: &str, port: u16, timeout: Duration) -> bool {
    let lookup = tokio::net::lookup_host((host, port));
    let Ok(Ok(addrs)) = tokio::time::timeout(timeout, lookup).await else {
        return false;
    };
    for addr in addrs {
        if let Ok(Ok(stream)) =
            tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await
        {
            drop(stream);
            return true;
        }
    }
    false
}

/// Bind an ephemeral port and immediately release it, so `kubectl` can claim
/// a port the kernel just told us was free.
fn free_local_port() -> Result<u16, String> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|e| format!("could not reserve a local port: {e}"))?;
    listener
        .local_addr()
        .map(|addr| addr.port())
        .map_err(|e| format!("could not read the reserved local port: {e}"))
}

async fn start_forward(
    argv: &[String],
    spec: &ForwardSpec,
) -> Result<(tokio::process::Child, u16), String> {
    let (program, rest) = argv
        .split_first()
        .ok_or("no kubectl command configured for port-forward")?;
    let port = free_local_port()?;
    let mut command = tokio::process::Command::new(program);
    command
        .args(rest)
        .arg(&spec.arg)
        .arg(format!("{port}:{}", spec.remote_port))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .map_err(|e| format!("failed to start port-forward for {}: {e}", spec.arg))?;
    wait_forward_ready(&mut child, port, &spec.arg).await?;
    Ok((child, port))
}

/// Poll the local end until it answers. A forward that exits early (RBAC, no
/// endpoints, port already bound) fails immediately rather than at the timeout.
async fn wait_forward_ready(
    child: &mut tokio::process::Child,
    port: u16,
    target: &str,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + FORWARD_READY_TIMEOUT;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("port-forward to {target} exited {status}"));
        }
        if reachable("127.0.0.1", port, FORWARD_POLL_INTERVAL).await {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!("port-forward to {target} did not become ready"));
        }
        tokio::time::sleep(FORWARD_POLL_INTERVAL).await;
    }
}

fn configure_command(command: &mut tokio::process::Command, url: &str, options: Options) {
    command
        .arg("--no-tui")
        // oha has no `--json`; the format is selected by name.
        .arg("--output-format")
        .arg("json")
        .arg("-z")
        .arg(format!("{}s", options.duration.as_secs()))
        .arg("-c")
        .arg(options.connections.to_string())
        .arg(url);
}

/// Run oha with bounded output memory. JSON is parsed directly from the child
/// pipe on one blocking worker so no full document is ever allocated.
async fn execute(
    executable: &Path,
    target: &Target,
    options: Options,
    route: Route,
    forward: Option<tokio::process::Child>,
) -> Result<ReportView, String> {
    // Held for the whole benchmark: dropping it kills the forward underneath.
    let _forward = forward;
    let url = target.url();
    let mut command = tokio::process::Command::new(executable);
    configure_command(&mut command, &url, options);
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
        .ok_or_else(|| "failed to capture oha stdout".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "failed to capture oha stderr".to_string())?;

    let runtime = tokio::runtime::Handle::current();
    let header = Header {
        url,
        route,
        options,
    };
    let parse_task = tokio::task::spawn_blocking(move || {
        parse_reader(BlockingReader::new(stdout, runtime), &header)
    });
    let stderr_task = tokio::spawn(read_stderr(stderr));

    let status = child
        .wait()
        .await
        .map_err(|e| format!("failed while waiting for oha: {e}"))?;
    let stderr = stderr_task
        .await
        .map_err(|e| format!("oha error reader failed: {e}"))?
        .unwrap_or_default();
    let parsed = parse_task
        .await
        .map_err(|e| format!("oha JSON parser failed: {e}"))?;

    if !status.success() {
        let detail = first_line(&stderr).unwrap_or("no error output");
        return Err(format!("oha exited {status}: {detail}"));
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

    /// `  label:      value`, aligned on a shared value column. A label wider
    /// than the column (an error message, say) still gets one space, so it
    /// never runs into its own value.
    fn push_field(&mut self, label: &str, value: &str) -> bool {
        let pad = FIELD_COLUMN.saturating_sub(label.len()).max(1);
        self.push(format!("  {label}{:pad$}{value}", ""))
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

/// What sofka knows before oha answers, reused in the report header.
struct Header {
    url: String,
    route: Route,
    options: Options,
}

/// oha emits `null` for every statistic it has no sample for — a run whose
/// requests were all aborted at the deadline reports nothing but nulls. Map
/// those to NaN, which the renderers already show as a dash, rather than
/// letting one absent number fail the whole parse.
fn nullable<'de, D: Deserializer<'de>>(deserializer: D) -> Result<f64, D::Error> {
    Ok(Option::<f64>::deserialize(deserializer)?.unwrap_or(f64::NAN))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Summary {
    #[serde(deserialize_with = "nullable")]
    success_rate: f64,
    #[serde(deserialize_with = "nullable")]
    total: f64,
    #[serde(deserialize_with = "nullable")]
    slowest: f64,
    #[serde(deserialize_with = "nullable")]
    fastest: f64,
    #[serde(deserialize_with = "nullable")]
    average: f64,
    #[serde(deserialize_with = "nullable")]
    requests_per_sec: f64,
    #[serde(deserialize_with = "nullable")]
    total_data: f64,
    #[serde(deserialize_with = "nullable")]
    size_per_request: f64,
}

/// An absent statistic is unknown, not zero.
impl Default for Summary {
    fn default() -> Self {
        Self {
            success_rate: f64::NAN,
            total: f64::NAN,
            slowest: f64::NAN,
            fastest: f64::NAN,
            average: f64::NAN,
            requests_per_sec: f64::NAN,
            total_data: f64::NAN,
            size_per_request: f64::NAN,
        }
    }
}

#[derive(Deserialize)]
#[serde(default)]
struct Percentiles {
    #[serde(deserialize_with = "nullable")]
    p50: f64,
    #[serde(deserialize_with = "nullable")]
    p90: f64,
    #[serde(deserialize_with = "nullable")]
    p95: f64,
    #[serde(deserialize_with = "nullable")]
    p99: f64,
    #[serde(rename = "p99.9", deserialize_with = "nullable")]
    p99_9: f64,
}

impl Default for Percentiles {
    fn default() -> Self {
        Self {
            p50: f64::NAN,
            p90: f64::NAN,
            p95: f64::NAN,
            p99: f64::NAN,
            p99_9: f64::NAN,
        }
    }
}

/// A `{key: count}` map rendered with a bounded number of rows. The running
/// total is accumulated before the cap so a truncated map still reports an
/// accurate request count.
#[derive(Default)]
struct Distribution {
    rows: Vec<(String, u64)>,
    total: u64,
    truncated: bool,
}

impl<'de> Deserialize<'de> for Distribution {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct DistributionVisitor;

        impl<'de> Visitor<'de> for DistributionVisitor {
            type Value = Distribution;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a map of counts")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Distribution, A::Error> {
                let mut out = Distribution::default();
                while let Some((key, count)) = map.next_entry::<String, u64>()? {
                    out.total = out.total.saturating_add(count);
                    if out.rows.len() < MAX_DISTRIBUTION_ROWS {
                        out.rows.push((key, count));
                    } else {
                        out.truncated = true;
                    }
                }
                Ok(out)
            }
        }

        deserializer.deserialize_map(DistributionVisitor)
    }
}

/// Only the four keys the report renders. Matching on a borrowed `&str` keeps
/// the parser from allocating a `String` for every key it then discards.
enum Field {
    Summary,
    Latency,
    StatusCodes,
    Errors,
    Other,
}

impl<'de> Deserialize<'de> for Field {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FieldVisitor;

        impl Visitor<'_> for FieldVisitor {
            type Value = Field;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an oha report field")
            }

            fn visit_str<E>(self, value: &str) -> Result<Field, E> {
                Ok(match value {
                    "summary" => Field::Summary,
                    "latencyPercentiles" => Field::Latency,
                    "statusCodeDistribution" => Field::StatusCodes,
                    "errorDistribution" => Field::Errors,
                    _ => Field::Other,
                })
            }
        }

        deserializer.deserialize_identifier(FieldVisitor)
    }
}

#[derive(Default)]
struct Envelope {
    summary: Summary,
    latency: Percentiles,
    status_codes: Distribution,
    errors: Distribution,
}

impl<'de> Deserialize<'de> for Envelope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EnvelopeVisitor;

        impl<'de> Visitor<'de> for EnvelopeVisitor {
            type Value = Envelope;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an oha JSON report")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Envelope, A::Error> {
                let mut out = Envelope::default();
                while let Some(field) = map.next_key::<Field>()? {
                    match field {
                        Field::Summary => out.summary = map.next_value()?,
                        Field::Latency => out.latency = map.next_value()?,
                        Field::StatusCodes => out.status_codes = map.next_value()?,
                        Field::Errors => out.errors = map.next_value()?,
                        // responseTimeHistogram and the rps breakdown are the
                        // bulk of the document and say nothing the summary and
                        // percentiles do not; skip them without building a tree.
                        Field::Other => {
                            map.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(out)
            }
        }

        deserializer.deserialize_map(EnvelopeVisitor)
    }
}

fn parse_reader(reader: impl Read, header: &Header) -> Result<ReportView, String> {
    let envelope: Envelope =
        serde_json::from_reader(reader).map_err(|e| format!("invalid JSON from oha: {e}"))?;
    Ok(format_report(envelope, header))
}

fn format_report(envelope: Envelope, header: &Header) -> ReportView {
    let requests = envelope
        .status_codes
        .total
        .saturating_add(envelope.errors.total);
    // A run with no completed requests reports no rate; downstream formatting
    // (the title and the status flash) needs a real number, not NaN.
    let rps = if envelope.summary.requests_per_sec.is_finite() {
        envelope.summary.requests_per_sec
    } else {
        0.0
    };
    let success_rate = normalized_rate(envelope.summary.success_rate);

    let mut lines = BoundedLines::default();
    lines.push_static("Summary");
    lines.push_field("url:", &header.url);
    lines.push_field("route:", header.route.label());
    lines.push_field(
        "requested:",
        &format!(
            "{}s, {} connections",
            header.options.duration.as_secs(),
            header.options.connections
        ),
    );
    lines.push_field("requests:", &thousands(requests));
    lines.push_field("success:", &format!("{success_rate:.2}%"));
    lines.push_field("rps:", &format!("{rps:.1}"));
    lines.push_field("elapsed:", &seconds(envelope.summary.total));
    lines.push_field(
        "data:",
        &format!(
            "{} ({} per request)",
            human_bytes(envelope.summary.total_data),
            human_bytes(envelope.summary.size_per_request)
        ),
    );

    lines.push_static("Latency");
    lines.push_field("fastest:", &seconds(envelope.summary.fastest));
    lines.push_field("average:", &seconds(envelope.summary.average));
    lines.push_field("slowest:", &seconds(envelope.summary.slowest));
    lines.push_field("p50:", &seconds(envelope.latency.p50));
    lines.push_field("p90:", &seconds(envelope.latency.p90));
    lines.push_field("p95:", &seconds(envelope.latency.p95));
    lines.push_field("p99:", &seconds(envelope.latency.p99));
    lines.push_field("p99.9:", &seconds(envelope.latency.p99_9));

    render_distribution(&mut lines, "Status codes", envelope.status_codes);
    render_distribution(&mut lines, "Errors", envelope.errors);

    let truncated = lines.truncated;
    ReportView {
        title: format!("oha — {} requests, {rps:.0} rps", thousands(requests)),
        lines: lines.finish(),
        requests,
        success_rate,
        requests_per_sec: rps,
        truncated,
    }
}

fn render_distribution(lines: &mut BoundedLines, heading: &str, mut distribution: Distribution) {
    if distribution.rows.is_empty() {
        return;
    }
    lines.push_static(heading);
    // Highest count first: the interesting row of a long tail is the top one.
    distribution
        .rows
        .sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    for (key, count) in distribution.rows {
        lines.push_field(&format!("{key}:"), &thousands(count));
    }
    if distribution.truncated {
        lines.truncated = true;
    }
}

/// oha reports a 0..1 fraction; tolerate a build that already scaled it.
fn normalized_rate(rate: f64) -> f64 {
    if !rate.is_finite() || rate < 0.0 {
        0.0
    } else if rate > 1.0 {
        rate
    } else {
        rate * 100.0
    }
}

fn thousands(value: u64) -> String {
    let raw = value.to_string();
    let mut out = String::with_capacity(raw.len() + raw.len() / 3);
    for (i, c) in raw.char_indices() {
        if i > 0 && (raw.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Latency is reported in fractional seconds; render it at a human scale.
fn seconds(value: f64) -> String {
    if !value.is_finite() || value < 0.0 {
        return "-".into();
    }
    if value < 0.001 {
        format!("{:.0}µs", value * 1_000_000.0)
    } else if value < 1.0 {
        format!("{:.1}ms", value * 1_000.0)
    } else {
        format!("{value:.2}s")
    }
}

fn human_bytes(value: f64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    if !value.is_finite() || value < 0.0 {
        return "-".into();
    }
    let mut scaled = value;
    let mut unit = 0;
    while scaled >= 1024.0 && unit < UNITS.len() - 1 {
        scaled /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{scaled:.0} {}", UNITS[unit])
    } else {
        format!("{scaled:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_report() -> &'static str {
        r#"{
            "summary": {
                "successRate": 1.0,
                "total": 10.0021,
                "slowest": 0.0512,
                "fastest": 0.0011,
                "average": 0.0087,
                "requestsPerSec": 1149.2,
                "totalData": 11764736,
                "sizePerRequest": 1024
            },
            "responseTimeHistogram": {"0.001": 5, "0.002": 900},
            "latencyPercentiles": {
                "p10": 0.002, "p25": 0.004, "p50": 0.0087, "p75": 0.012,
                "p90": 0.018, "p95": 0.0214, "p99": 0.0481,
                "p99.9": 0.0502, "p99.99": 0.0511
            },
            "rps": {"mean": 1149.2, "stddev": 12.3, "max": 1200.0, "min": 1100.0},
            "statusCodeDistribution": {"200": 11490, "503": 2},
            "errorDistribution": {"connection error": 3}
        }"#
    }

    fn header() -> Header {
        Header {
            url: "http://10.0.0.5:80/".into(),
            route: Route::Direct,
            options: Options::default(),
        }
    }

    /// Captured verbatim from `oha 1.16.0 --no-tui --output-format json`
    /// against a local server. Guards the field names and shapes sofka reads.
    const REAL_REPORT: &str = r#"{"summary":{"successRate":1.0,"total":3.003860875,"slowest":0.577411167,"fastest":0.000217667,"average":0.0013785588666112064,"requestsPerSec":7205.726530194245,"totalData":22155264,"sizePerRequest":1024,"sizePerSec":7375595.915373411},"metrics":{"success_rate":1.0,"requests_per_sec":7205.726530194245,"latency_ms":{"min":0.218,"mean":1.379,"p50":0.635,"p95":1.444,"p99":31.009,"max":577.411}},"responseTimeHistogram":{"0.000217667":1,"0.057937016999999986":21581,"0.11565636699999998":46,"0.17337571699999996":5,"0.23109506699999996":1,"0.28881441699999993":0,"0.3465337669999999":1,"0.4042531169999999":0,"0.4619724669999999":0,"0.5196918169999999":0,"0.577411167":1},"latencyPercentiles":{"p10":0.000489167,"p25":0.000546083,"p50":0.000635,"p75":0.000788792,"p90":0.001105292,"p95":0.001443542,"p99":0.031008791,"p99.9":0.062437375,"p99.99":0.213679625},"firstByteHistogram":{"0.000217542":1,"0.057936892000000004":21581,"0.115656242":46,"0.173375592":5,"0.231094942":1,"0.28881429200000003":0,"0.34653364200000003":1,"0.40425299200000003":0,"0.46197234200000004":0,"0.519691692":0,"0.577411042":1},"firstBytePercentiles":{"p10":0.000488917,"p25":0.000545875,"p50":0.00063475,"p75":0.000788583,"p90":0.001105,"p95":0.001443083,"p99":0.031007875,"p99.9":0.062437209,"p99.99":0.213679541},"rps":{"mean":7214.654144857673,"stddev":1977.3054433858795,"max":10193.268405914241,"min":55.88062244978343,"percentiles":{"p10":4384.973073133207,"p25":5835.156819839519,"p50":8023.93781367966,"p75":8775.173400452317,"p90":9109.94441532348,"p95":9238.146153095686,"p99":9572.666980663724,"p99.9":10193.268405914241,"p99.99":10193.268405914241}},"details":{"DNSDialup":{"average":0.0007011326414771668,"fastest":2.2208e-05,"slowest":0.576819792},"DNSLookup":{"average":1.8877397393233527e-06,"fastest":7.5e-07,"slowest":0.000195667},"firstByte":{"average":0.0013783326095396593,"fastest":0.000217542,"slowest":0.577411042}},"statusCodeDistribution":{"200":21636},"errorDistribution":{"aborted due to deadline":9}}"#;

    /// The same command when every request was aborted at the deadline: oha
    /// reports `null` for each statistic it never sampled.
    const REAL_EMPTY_REPORT: &str = r#"{"summary":{"successRate":null,"total":2.004223334,"slowest":null,"fastest":null,"average":null,"requestsPerSec":2.4947319568528683,"totalData":0,"sizePerRequest":null,"sizePerSec":0.0},"metrics":{"success_rate":null,"requests_per_sec":2.4947319568528683,"latency_ms":{"min":null,"mean":null,"p50":null,"p95":null,"p99":null,"max":null}},"responseTimeHistogram":{"NaN":0},"latencyPercentiles":{"p10":null,"p25":null,"p50":null,"p75":null,"p90":null,"p95":null,"p99":null,"p99.9":null,"p99.99":null},"firstByteHistogram":{"NaN":0},"firstBytePercentiles":{"p10":null,"p25":null,"p50":null,"p75":null,"p90":null,"p95":null,"p99":null,"p99.9":null,"p99.99":null},"rps":{"mean":null,"stddev":null,"max":null,"min":null,"percentiles":{"p10":null,"p25":null,"p50":null,"p75":null,"p90":null,"p95":null,"p99":null,"p99.9":null,"p99.99":null}},"details":{"DNSDialup":{"average":null,"fastest":null,"slowest":null},"DNSLookup":{"average":null,"fastest":null,"slowest":null},"firstByte":{"average":null,"fastest":null,"slowest":null}},"statusCodeDistribution":{},"errorDistribution":{"aborted due to deadline":5}}"#;

    #[test]
    fn parses_a_real_oha_1_16_report() {
        let report = parse_reader(REAL_REPORT.as_bytes(), &header()).unwrap();
        // 21,636 served plus the 9 aborted at the deadline.
        assert_eq!(report.requests, 21_645);
        assert!((report.success_rate - 100.0).abs() < f64::EPSILON);
        assert!((report.requests_per_sec - 7_205.726_530_194_245).abs() < 1e-9);
        assert!(!report.truncated);
        let body = report.lines.join("\n");
        assert!(body.contains("requests:    21,645"), "{body}");
        assert!(body.contains("success:     100.00%"), "{body}");
        assert!(body.contains("rps:         7205.7"), "{body}");
        assert!(body.contains("elapsed:     3.00s"), "{body}");
        assert!(body.contains("fastest:     218µs"), "{body}");
        assert!(body.contains("p50:         635µs"), "{body}");
        assert!(body.contains("p99:         31.0ms"), "{body}");
        assert!(body.contains("200:         21,636"), "{body}");
        assert!(body.contains("aborted due to deadline: 9"), "{body}");
        assert!(
            body.contains("data:        21.1 MiB (1.0 KiB per request)"),
            "{body}"
        );
    }

    #[test]
    fn a_run_with_no_completed_requests_still_reports() {
        // Every statistic is null here; before nulls were tolerated this
        // failed the whole parse and the user saw a JSON error instead of the
        // aborted-request count that explains what went wrong.
        let report = parse_reader(REAL_EMPTY_REPORT.as_bytes(), &header()).unwrap();
        assert_eq!(report.requests, 5);
        assert_eq!(report.success_rate, 0.0);
        // rps is real in this document even though the latencies are not.
        assert!((report.requests_per_sec - 2.494_731_956_852_868_3).abs() < 1e-12);
        let body = report.lines.join("\n");
        assert!(body.contains("success:     0.00%"), "{body}");
        // Unsampled statistics read as a dash, never as a misleading zero.
        assert!(body.contains("p99:         -"), "{body}");
        assert!(body.contains("average:     -"), "{body}");
        assert!(body.contains("aborted due to deadline: 5"), "{body}");
    }

    #[test]
    fn options_default_to_a_conservative_run() {
        let options = parse_options("").unwrap();
        assert_eq!(options.duration, Duration::from_secs(10));
        assert_eq!(options.connections, 20);
    }

    #[test]
    fn options_accept_duration_then_connections() {
        assert_eq!(
            parse_options("30s").unwrap(),
            Options {
                duration: Duration::from_secs(30),
                connections: 20,
                port: None,
            }
        );
        assert_eq!(
            parse_options("2m 100").unwrap(),
            Options {
                duration: Duration::from_secs(120),
                connections: 100,
                port: None,
            }
        );
        // A bare number is seconds.
        assert_eq!(
            parse_options("45").unwrap().duration,
            Duration::from_secs(45)
        );
    }

    #[test]
    fn options_are_capped_and_validated_before_any_process_starts() {
        assert!(parse_options("99h").is_err());
        assert!(parse_options("6m").unwrap_err().contains("cap"));
        assert!(parse_options("10s 200001").unwrap_err().contains("cap"));
        // Well inside the raised ceiling.
        assert_eq!(parse_options("10s 10000").unwrap().connections, 10_000);
        assert_eq!(parse_options("10s 200000").unwrap().connections, 200_000);
        assert!(parse_options("0s").is_err());
        assert!(parse_options("10s 0").is_err());
        assert!(parse_options("soon").is_err());
        assert!(parse_options("10s 20 extra").unwrap_err().contains("usage"));
    }

    #[test]
    fn ingress_resolves_host_path_and_tls() {
        let obj = json!({
            "spec": {
                "tls": [{"hosts": ["app.example.com"]}],
                "rules": [{
                    "host": "app.example.com",
                    "http": {"paths": [{"path": "/api"}]}
                }]
            }
        });
        let plan = plan("ingresses", "web", &obj, None).unwrap();
        let direct = plan.direct.unwrap();
        assert_eq!(direct.url(), "https://app.example.com:443/api");
        // An ingress is fronted by a controller, not one forwardable pod.
        assert!(plan.forward.is_none());
    }

    #[test]
    fn ingress_without_tls_falls_back_to_http_and_root() {
        let obj = json!({"spec": {"rules": [{"host": "app.example.com"}]}});
        let direct = plan("ingresses", "web", &obj, None)
            .unwrap()
            .direct
            .unwrap();
        assert_eq!(direct.url(), "http://app.example.com:80/");
    }

    #[test]
    fn ingress_without_a_host_uses_the_load_balancer_address() {
        let obj = json!({
            "spec": {"rules": [{"http": {"paths": [{"path": "/"}]}}]},
            "status": {"loadBalancer": {"ingress": [{"ip": "10.0.0.5"}]}}
        });
        let direct = plan("ingresses", "web", &obj, None)
            .unwrap()
            .direct
            .unwrap();
        assert_eq!(direct.host, "10.0.0.5");
    }

    #[test]
    fn wildcard_certificates_cover_one_label_only() {
        assert!(tls_host_matches("*.example.com", "api.example.com"));
        assert!(!tls_host_matches("*.example.com", "example.com"));
        assert!(!tls_host_matches("*.example.com", "a.b.example.com"));
        assert!(tls_host_matches("app.example.com", "APP.example.com"));
    }

    #[test]
    fn regex_ingress_paths_degrade_to_root() {
        assert_eq!(normalize_path("/api"), "/api");
        assert_eq!(normalize_path("/api/v1"), "/api/v1");
        assert_eq!(normalize_path("/api(/|$)(.*)"), "/");
        assert_eq!(normalize_path("api"), "/");
        assert_eq!(normalize_path(""), "/");
    }

    #[test]
    fn service_prefers_the_load_balancer_address_and_always_offers_a_forward() {
        let obj = json!({
            "spec": {"type": "LoadBalancer", "clusterIP": "10.96.0.12", "ports": [{"port": 80}]},
            "status": {"loadBalancer": {"ingress": [{"hostname": "lb.example.com"}]}}
        });
        let plan = plan("services", "web", &obj, None).unwrap();
        assert_eq!(plan.direct.unwrap().url(), "http://lb.example.com:80/");
        let forward = plan.forward.unwrap();
        assert_eq!(forward.arg, "svc/web");
        assert_eq!(forward.remote_port, 80);
    }

    #[test]
    fn cluster_ip_is_still_worth_probing_but_headless_is_not() {
        let routable = json!({"spec": {"clusterIP": "10.96.0.12", "ports": [{"port": 8080}]}});
        assert_eq!(
            plan("services", "web", &routable, None)
                .unwrap()
                .direct
                .unwrap()
                .host,
            "10.96.0.12"
        );
        let headless = json!({"spec": {"clusterIP": "None", "ports": [{"port": 8080}]}});
        let plan = plan("services", "web", &headless, None).unwrap();
        assert!(plan.direct.is_none());
        // No address of its own, but the forward still reaches it.
        assert!(plan.forward.is_some());
    }

    #[test]
    fn https_is_inferred_from_app_protocol_name_or_well_known_port() {
        let by_protocol = json!({"spec": {"clusterIP": "10.0.0.1", "ports": [{"port": 8080, "appProtocol": "https"}]}});
        assert_eq!(
            plan("services", "s", &by_protocol, None)
                .unwrap()
                .direct
                .unwrap()
                .scheme,
            "https"
        );
        let by_name =
            json!({"spec": {"clusterIP": "10.0.0.1", "ports": [{"port": 9000, "name": "https"}]}});
        assert_eq!(
            plan("services", "s", &by_name, None)
                .unwrap()
                .direct
                .unwrap()
                .scheme,
            "https"
        );
        let by_port = json!({"spec": {"clusterIP": "10.0.0.1", "ports": [{"port": 443}]}});
        assert_eq!(
            plan("services", "s", &by_port, None)
                .unwrap()
                .direct
                .unwrap()
                .scheme,
            "https"
        );
        let plain = json!({"spec": {"clusterIP": "10.0.0.1", "ports": [{"port": 80}]}});
        assert_eq!(
            plan("services", "s", &plain, None)
                .unwrap()
                .direct
                .unwrap()
                .scheme,
            "http"
        );
    }

    #[test]
    fn a_multi_port_service_is_benchmarked_on_the_port_that_declares_http() {
        // grpc is declared first; a TCP probe cannot tell it is the wrong one.
        let obj = json!({
            "spec": {
                "clusterIP": "10.96.0.12",
                "ports": [
                    {"name": "grpc", "port": 9000},
                    {"name": "http", "port": 8080}
                ]
            }
        });
        let plan = plan("services", "web", &obj, None).unwrap();
        assert_eq!(plan.direct.unwrap().port, 8080);
        assert_eq!(plan.forward.unwrap().remote_port, 8080);
    }

    #[test]
    fn app_protocol_also_identifies_the_http_port() {
        let obj = json!({
            "spec": {
                "clusterIP": "10.96.0.12",
                "ports": [
                    {"name": "metrics", "port": 9090},
                    {"appProtocol": "https", "port": 8443}
                ]
            }
        });
        let direct = plan("services", "web", &obj, None).unwrap().direct.unwrap();
        assert_eq!(direct.port, 8443);
        assert_eq!(direct.scheme, "https");
    }

    #[test]
    fn a_conventional_http_port_number_beats_an_earlier_unremarkable_one() {
        let obj = json!({
            "spec": {
                "clusterIP": "10.96.0.12",
                "ports": [{"port": 9000}, {"port": 8080}]
            }
        });
        let direct = plan("services", "web", &obj, None).unwrap().direct.unwrap();
        assert_eq!(direct.port, 8080);
    }

    #[test]
    fn nothing_to_distinguish_them_keeps_the_first_declared_port() {
        let obj = json!({
            "spec": {
                "clusterIP": "10.96.0.12",
                "ports": [{"port": 9000}, {"port": 9001}]
            }
        });
        let direct = plan("services", "web", &obj, None).unwrap().direct.unwrap();
        assert_eq!(direct.port, 9000);
    }

    #[test]
    fn protocol_prefixed_port_names_are_understood() {
        // Kubernetes and Istio spell these `http-web` / `grpc-api`, not `http`.
        let obj = json!({
            "spec": {
                "clusterIP": "10.96.0.12",
                "ports": [
                    {"name": "grpc-api", "port": 9000},
                    {"name": "http-web", "port": 7070}
                ]
            }
        });
        let direct = plan("services", "web", &obj, None).unwrap().direct.unwrap();
        assert_eq!(direct.port, 7070);
        assert_eq!(direct.scheme, "http");

        let secure = json!({
            "spec": {
                "clusterIP": "10.96.0.12",
                "ports": [{"name": "https-web", "port": 7443}]
            }
        });
        assert_eq!(
            plan("services", "web", &secure, None)
                .unwrap()
                .direct
                .unwrap()
                .scheme,
            "https"
        );
    }

    #[test]
    fn a_port_that_names_no_protocol_still_beats_one_that_names_a_non_http_protocol() {
        // The HTTP endpoint here says nothing at all, and its number is not
        // conventional either — but `grpc` is a definite no, so it loses.
        let obj = json!({
            "spec": {
                "clusterIP": "10.96.0.12",
                "ports": [{"name": "grpc", "port": 9000}, {"name": "web", "port": 7070}]
            }
        });
        let direct = plan("services", "web", &obj, None).unwrap().direct.unwrap();
        assert_eq!(direct.port, 7070);
    }

    #[test]
    fn a_lone_non_http_port_is_still_benchmarked() {
        // Ranking only orders candidates; it never leaves the object without
        // one. Benchmarking grpc will fail, but with oha's error, not ours.
        let obj = json!({
            "spec": {"clusterIP": "10.96.0.12", "ports": [{"name": "grpc", "port": 9000}]}
        });
        let direct = plan("services", "web", &obj, None).unwrap().direct.unwrap();
        assert_eq!(direct.port, 9000);
    }

    #[test]
    fn an_explicit_port_overrides_the_choice_and_must_exist() {
        let obj = json!({
            "spec": {
                "clusterIP": "10.96.0.12",
                "ports": [{"name": "http", "port": 8080}, {"name": "admin", "port": 9000}]
            }
        });
        let plan_admin = plan("services", "web", &obj, Some(9000)).unwrap();
        assert_eq!(plan_admin.direct.unwrap().port, 9000);
        assert_eq!(plan_admin.forward.unwrap().remote_port, 9000);
        // A port the object does not declare fails loudly rather than
        // forwarding to something that cannot answer.
        let error = plan("services", "web", &obj, Some(1234)).unwrap_err();
        assert!(error.contains("not declared by this service"), "{error}");
    }

    #[test]
    fn a_pods_http_port_is_found_across_all_containers() {
        let obj = json!({
            "spec": {"containers": [
                {"name": "sidecar", "ports": [{"name": "grpc", "containerPort": 9000}]},
                {"name": "app", "ports": [{"name": "http", "containerPort": 8080}]}
            ]},
            "status": {"podIP": "10.244.1.7"}
        });
        let chosen = plan("pods", "api-0", &obj, None).unwrap();
        assert_eq!(chosen.direct.unwrap().port, 8080);
        let error = plan("pods", "api-0", &obj, Some(1234)).unwrap_err();
        assert!(error.contains("not declared by this pod"), "{error}");
    }

    #[test]
    fn an_explicit_ingress_port_replaces_the_scheme_default() {
        let obj = json!({"spec": {"rules": [{"host": "app.example.com"}]}});
        let direct = plan("ingresses", "web", &obj, Some(8080))
            .unwrap()
            .direct
            .unwrap();
        assert_eq!(direct.url(), "http://app.example.com:8080/");
    }

    #[test]
    fn a_named_port_argument_is_position_independent() {
        assert_eq!(parse_options("port=8080").unwrap().port, Some(8080));
        assert_eq!(
            parse_options("30s 100 port=8080").unwrap(),
            Options {
                duration: Duration::from_secs(30),
                connections: 100,
                port: Some(8080),
            }
        );
        // Named, so a bare number is never ambiguous with a duration.
        assert_eq!(
            parse_options("port=8080 30s").unwrap().duration,
            Duration::from_secs(30)
        );
        assert!(parse_options("port=0").is_err());
        assert!(parse_options("port=nope").is_err());
        assert!(parse_options("port=99999").is_err());
    }

    #[test]
    fn pod_uses_its_ip_and_first_container_port() {
        let obj = json!({
            "spec": {"containers": [{"ports": [{"containerPort": 8080}]}]},
            "status": {"podIP": "10.244.1.7"}
        });
        let plan = plan("pods", "api-0", &obj, None).unwrap();
        assert_eq!(plan.direct.unwrap().url(), "http://10.244.1.7:8080/");
        assert_eq!(plan.forward.unwrap().arg, "pod/api-0");
    }

    #[test]
    fn ipv6_authorities_are_bracketed() {
        let target = Target {
            scheme: "http",
            host: "fd00::1".into(),
            port: 80,
            path: "/".into(),
        };
        assert_eq!(target.url(), "http://[fd00::1]:80/");
    }

    #[test]
    fn unsupported_kinds_and_portless_objects_are_refused() {
        assert!(plan("deployments", "web", &json!({}), None).is_err());
        assert!(plan("services", "web", &json!({"spec": {}}), None).is_err());
        assert!(plan("pods", "web", &json!({"spec": {"containers": []}}), None).is_err());
    }

    #[test]
    fn command_is_non_interactive_json_with_the_url_last() {
        let mut command = tokio::process::Command::new("oha");
        configure_command(
            &mut command,
            "http://10.0.0.5:80/",
            Options {
                duration: Duration::from_secs(30),
                connections: 100,
                port: None,
            },
        );
        let args = command.as_std().get_args().collect::<Vec<_>>();
        assert_eq!(
            args,
            [
                "--no-tui",
                "--output-format",
                "json",
                "-z",
                "30s",
                "-c",
                "100",
                "http://10.0.0.5:80/",
            ]
        );
    }

    #[test]
    fn parses_and_formats_an_oha_report() {
        let report = parse_reader(sample_report().as_bytes(), &header()).unwrap();
        assert_eq!(report.requests, 11_495);
        assert_eq!(report.title, "oha — 11,495 requests, 1149 rps");
        assert!((report.success_rate - 100.0).abs() < f64::EPSILON);
        assert!(!report.truncated);
        let body = report.lines.join("\n");
        assert!(body.contains("url:         http://10.0.0.5:80/"), "{body}");
        assert!(body.contains("route:       direct"), "{body}");
        assert!(body.contains("requested:   10s, 20 connections"), "{body}");
        assert!(body.contains("p99:         48.1ms"), "{body}");
        assert!(body.contains("average:     8.7ms"), "{body}");
        assert!(
            body.contains("data:        11.2 MiB (1.0 KiB per request)"),
            "{body}"
        );
        // Highest count first, so a long tail does not bury the common case.
        let codes = body.find("200:").unwrap();
        assert!(codes < body.find("503:").unwrap(), "{body}");
        assert!(body.contains("connection error:"), "{body}");
    }

    #[test]
    fn an_empty_error_map_renders_no_error_section() {
        let json = r#"{"summary":{"successRate":1.0},"statusCodeDistribution":{"200":5},"errorDistribution":{}}"#;
        let report = parse_reader(json.as_bytes(), &header()).unwrap();
        assert!(!report.lines.iter().any(|l| l == "Errors"));
        assert_eq!(report.requests, 5);
    }

    #[test]
    fn malformed_json_is_actionable() {
        let error = parse_reader(b"not json".as_slice(), &header()).unwrap_err();
        assert!(error.contains("invalid JSON from oha"), "{error}");
    }

    #[test]
    fn a_huge_status_distribution_stays_bounded() {
        let mut codes =
            String::from("{\"summary\":{\"successRate\":1.0},\"statusCodeDistribution\":{");
        for i in 0..5_000 {
            if i > 0 {
                codes.push(',');
            }
            codes.push_str(&format!("\"code-{i}\":1"));
        }
        codes.push_str("}}");
        let report = parse_reader(codes.as_bytes(), &header()).unwrap();
        // Every entry still counts toward the total, only the rows are capped.
        assert_eq!(report.requests, 5_000);
        assert!(report.truncated);
        assert!(
            report.lines.len() <= REPORT_MAX_LINES,
            "{}",
            report.lines.len()
        );
        let bytes: usize = report.lines.iter().map(String::len).sum();
        assert!(bytes <= REPORT_MAX_BYTES, "{bytes}");
        assert_eq!(report.lines.last().unwrap(), TRUNCATION_LINE);
    }

    #[test]
    fn latency_is_rendered_at_a_human_scale() {
        assert_eq!(seconds(0.0000123), "12µs");
        assert_eq!(seconds(0.0087), "8.7ms");
        assert_eq!(seconds(1.5), "1.50s");
        assert_eq!(seconds(f64::NAN), "-");
        assert_eq!(thousands(11_495), "11,495");
        assert_eq!(thousands(7), "7");
        assert_eq!(human_bytes(512.0), "512 B");
        assert_eq!(human_bytes(11_764_736.0), "11.2 MiB");
    }

    #[test]
    fn a_success_rate_already_scaled_to_percent_is_left_alone() {
        assert!((normalized_rate(1.0) - 100.0).abs() < f64::EPSILON);
        assert!((normalized_rate(0.5) - 50.0).abs() < f64::EPSILON);
        assert!((normalized_rate(99.5) - 99.5).abs() < f64::EPSILON);
        assert_eq!(normalized_rate(f64::NAN), 0.0);
    }

    #[tokio::test]
    async fn reachability_distinguishes_a_live_listener_from_a_closed_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(reachable("127.0.0.1", port, PROBE_TIMEOUT).await);
        drop(listener);
        assert!(!reachable("127.0.0.1", port, PROBE_TIMEOUT).await);
        // An unresolvable host must fail the probe, not hang it.
        assert!(!reachable("no-such-host.invalid", 80, PROBE_TIMEOUT).await);
    }

    /// Live test against a real oha binary — opt-in:
    /// `cargo test -- --ignored` with `oha` on PATH. Guards the argv and the
    /// JSON field names against an oha release changing either.
    #[tokio::test]
    #[ignore]
    async fn e2e_real_oha_benchmarks_a_local_server() {
        use tokio::io::AsyncWriteExt;

        let executable = detect().expect("oha not found on PATH");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Minimal keep-alive HTTP/1.1 server: enough for oha to complete real
        // requests and report real status codes.
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 2048];
                    while socket.read(&mut buf).await.is_ok_and(|n| n > 0) {
                        if socket
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                });
            }
        });

        let report = run(Launch {
            executable,
            plan: Plan {
                direct: Some(Target {
                    scheme: "http",
                    host: "127.0.0.1".into(),
                    port,
                    path: "/".into(),
                }),
                forward: None,
            },
            options: Options {
                duration: Duration::from_secs(2),
                connections: 5,
                port: None,
            },
            existing_local_port: None,
            forward_argv: Vec::new(),
        })
        .await
        .expect("real oha run failed");

        assert!(report.requests > 0, "{report:?}");
        assert!(report.requests_per_sec > 0.0, "{report:?}");
        assert!(report.success_rate > 0.0, "{report:?}");
        assert!(
            report
                .lines
                .iter()
                .any(|l| l.contains("route:       direct")),
            "{:?}",
            report.lines
        );
        assert!(
            report.lines.iter().any(|l| l.starts_with("  200:")),
            "{:?}",
            report.lines
        );
    }

    #[cfg(unix)]
    #[test]
    fn path_detection_requires_an_executable_and_honours_path_order() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!(
            "sofka-oha-detect-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let first = root.join("first");
        let second = root.join("second");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();

        // Present but not executable: skipped in favour of the later directory.
        std::fs::write(first.join("oha"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(first.join("oha"), std::fs::Permissions::from_mode(0o644))
            .unwrap();
        std::fs::write(second.join("oha"), "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(second.join("oha"), std::fs::Permissions::from_mode(0o755))
            .unwrap();

        let path = std::env::join_paths([&first, &second]).unwrap();
        assert_eq!(detect_in_path(&path), Some(second.join("oha")));

        std::fs::set_permissions(first.join("oha"), std::fs::Permissions::from_mode(0o755))
            .unwrap();
        assert_eq!(detect_in_path(&path), Some(first.join("oha")));

        std::fs::remove_dir_all(root).unwrap();
    }
}
