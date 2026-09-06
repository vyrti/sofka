//! The `:sanitize` core plugin: delete the pods a namespace has finished with.
//!
//! Runs as `sofka --plugin-adapter sanitize`, spawned by the plugin runner like
//! any other package. It speaks the same request/report protocol over stdin and
//! stdout, so guardrails, read-only mode, confirmation, and the report view all
//! apply unchanged — the only difference from an external package is that the
//! adapter ships inside the binary instead of needing a runtime on PATH.

use anyhow::{Context, Result};
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, DeleteParams, ListParams, Preconditions};
use kube::core::DynamicObject;
use kube::{Client, Config};
use serde_json::{Value, json};

/// Statuses that mean the pod is finished and will not come back on its own.
const TERMINAL: &[&str] = &[
    "Succeeded",
    "Failed",
    "Error",
    "OOMKilled",
    "ContainerStatusUnknown",
];
/// Terminal, plus the pods that are wedged and will not recover unaided.
const STUCK: &[&str] = &["CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull"];
/// Everything above, plus pods that have not started. This is the k9s set;
/// `Pending` covers a pod that is merely waiting for a node, so it is opt-in.
const UNSTARTED: &[&str] = &["Pending"];

/// Rows per report table. The runner caps captured output at 1 MiB.
const MAX_ROWS: usize = 500;

fn wanted(states: &str) -> Option<Vec<&'static str>> {
    let mut set = TERMINAL.to_vec();
    match states {
        "terminal" => {}
        "stuck" => set.extend_from_slice(STUCK),
        "all" => {
            set.extend_from_slice(STUCK);
            set.extend_from_slice(UNSTARTED);
        }
        _ => return None,
    }
    set.sort_unstable();
    Some(set)
}

/// Whether an application container is still running.
///
/// The STATUS column reports the reason of the last container that terminated,
/// so a multi-container pod reads `OOMKilled` while a sibling still serves. That
/// is right for a column and wrong for a delete. Readiness is deliberately not
/// part of this: a container failing its readiness probe, or still inside its
/// startup probe, is out of the load balancer and very much alive.
///
/// Restartable init containers (native sidecars) are deliberately not consulted.
/// They are infrastructure for the workload rather than the workload, and
/// counting them would make an identical crash-looping pod exempt from
/// `states = stuck` purely because something injected a proxy into it. The
/// STATUS column ignores them for the same reason, so the two agree.
fn running(pod: &Pod) -> bool {
    pod.status
        .as_ref()
        .and_then(|s| s.container_statuses.as_ref())
        .is_some_and(|cs| {
            cs.iter()
                .any(|c| c.state.as_ref().is_some_and(|s| s.running.is_some()))
        })
}

/// A pod's status as the pods view shows it, so `states` names what the user reads.
fn status_of(pod: &Pod) -> Result<String> {
    let object: DynamicObject = serde_json::from_value(serde_json::to_value(pod)?)?;
    Ok(crate::columns::pod_status(&object))
}

struct Target {
    namespace: String,
    name: String,
    uid: String,
    status: String,
}

/// Read the request, sanitize, and write the report. Errors here are execution
/// errors: the runner shows them and no report is produced.
pub async fn run() -> Result<()> {
    let request: Value = serde_json::from_reader(std::io::stdin().lock())
        .context("reading the plugin request from stdin")?;
    if request.get("schema_version").and_then(Value::as_u64) != Some(1) {
        anyhow::bail!("unsupported request schema_version");
    }

    let inputs = request.get("inputs").cloned().unwrap_or_else(|| json!({}));
    let states = inputs
        .get("states")
        .and_then(Value::as_str)
        .unwrap_or("terminal");
    let wanted = wanted(states).with_context(|| format!("unknown states value '{states}'"))?;
    let dry_run = inputs.get("dry_run").and_then(Value::as_str) == Some("true");

    let namespace = request
        .get("namespace")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();

    let client = client_for(request.get("context").and_then(Value::as_str)).await?;
    let api: Api<Pod> = if namespace.is_empty() {
        Api::all(client.clone())
    } else {
        Api::namespaced(client.clone(), &namespace)
    };

    let mut targets = Vec::new();
    for pod in api
        .list(&ListParams::default())
        .await
        .context("listing pods")?
    {
        let status = status_of(&pod)?;
        if !wanted.contains(&status.as_str()) || running(&pod) {
            continue;
        }
        let meta = &pod.metadata;
        targets.push(Target {
            namespace: meta.namespace.clone().unwrap_or_default(),
            name: meta.name.clone().unwrap_or_default(),
            uid: meta.uid.clone().unwrap_or_default(),
            status,
        });
    }
    targets.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));

    let matched = targets.len();
    let mut deleted = Vec::new();
    let mut failed = Vec::new();
    let mut replaced = 0usize;

    if !dry_run {
        for target in &targets {
            // The UID precondition binds the delete to the object that scanned.
            // A pod name is reusable, so without it a StatefulSet that recreated
            // `db-0` in the meantime would lose its healthy replacement instead.
            let params = DeleteParams {
                preconditions: Some(Preconditions {
                    uid: Some(target.uid.clone()),
                    resource_version: None,
                }),
                ..DeleteParams::default()
            };
            let api: Api<Pod> = Api::namespaced(client.clone(), &target.namespace);
            match api.delete(&target.name, &params).await {
                Ok(_) => deleted.push(target),
                // 409 is the precondition failing: the name now holds a
                // different object. 404 means someone got there first. Neither
                // is an error, and neither is a pod we should report as gone.
                Err(kube::Error::Api(e)) if e.code == 409 || e.code == 404 => replaced += 1,
                Err(e) => failed.push(vec![
                    target.namespace.clone(),
                    target.name.clone(),
                    e.to_string(),
                ]),
            }
        }
    }

    let scope = if namespace.is_empty() {
        "all namespaces".to_string()
    } else {
        format!("namespace {namespace}")
    };
    let mut summary = vec![
        format!("Scanned {scope}."),
        format!("Matching statuses: {}.", wanted.join(", ")),
    ];
    if dry_run {
        summary.push(format!("{matched} matched; nothing deleted (dry run)."));
    } else {
        summary.push(format!(
            "{matched} matched, {} deleted, {} failed.",
            deleted.len(),
            failed.len()
        ));
        if replaced > 0 {
            summary.push(format!(
                "{replaced} replaced since the scan and left alone."
            ));
        }
    }

    let mut sections = vec![json!({"title": "Summary", "lines": summary})];
    if !failed.is_empty() {
        sections.push(table("Failed", &["Namespace", "Pod", "Error"], failed));
    }
    let listed: Vec<&Target> = if dry_run {
        targets.iter().collect()
    } else {
        deleted
    };
    let rows: Vec<Vec<String>> = listed
        .iter()
        .map(|t| vec![t.namespace.clone(), t.name.clone(), t.status.clone()])
        .collect();
    if !rows.is_empty() {
        let title = if dry_run { "Would delete" } else { "Deleted" };
        sections.push(table(title, &["Namespace", "Pod", "Status"], rows));
    }

    serde_json::to_writer(
        std::io::stdout().lock(),
        &json!({"schema_version": 1, "title": "Sanitize pods", "sections": sections}),
    )
    .context("writing the report")
}

fn table(title: &str, columns: &[&str], rows: Vec<Vec<String>>) -> Value {
    let total = rows.len();
    let mut section = json!({
        "title": title,
        "columns": columns,
        "rows": rows.into_iter().take(MAX_ROWS).collect::<Vec<_>>(),
    });
    if total > MAX_ROWS {
        section["lines"] = json!([format!("{} more rows not shown.", total - MAX_ROWS)]);
    }
    section
}

/// Build a client for the request's context. A null context means sofka had no
/// explicit kubeconfig context name, so let the usual inference apply.
async fn client_for(context: Option<&str>) -> Result<Client> {
    let config = match context {
        Some(name) => {
            let options = kube::config::KubeConfigOptions {
                context: Some(name.to_string()),
                cluster: None,
                user: None,
            };
            let kubeconfig = kube::config::Kubeconfig::read().context("reading kubeconfig")?;
            Config::from_custom_kubeconfig(kubeconfig, &options)
                .await
                .with_context(|| format!("building config for context '{name}'"))?
        }
        None => Config::infer().await.context("loading kubeconfig")?,
    };
    Client::try_from(config).context("building a Kubernetes client")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn pod(value: Value) -> Pod {
        serde_json::from_value(value).expect("pod fixture")
    }

    #[test]
    fn state_sets_widen_in_order() {
        let terminal = wanted("terminal").unwrap();
        let stuck = wanted("stuck").unwrap();
        let all = wanted("all").unwrap();
        assert!(terminal.contains(&"Succeeded") && terminal.contains(&"Failed"));
        assert!(!terminal.contains(&"CrashLoopBackOff"));
        assert!(stuck.contains(&"CrashLoopBackOff") && !stuck.contains(&"Pending"));
        assert!(all.contains(&"Pending"));
        assert!(terminal.len() < stuck.len() && stuck.len() < all.len());
        assert!(wanted("bogus").is_none());
    }

    #[test]
    fn status_matches_the_pods_view() {
        // The sets name what the STATUS column shows, not what k9s would print:
        // a finished pod reads Succeeded here, never Completed.
        let finished = pod(json!({
            "metadata": {"name": "job", "namespace": "default"},
            "status": {"phase": "Succeeded", "containerStatuses": [
                {"name": "c", "ready": false, "restartCount": 0,
                 "state": {"terminated": {"reason": "Completed", "exitCode": 0}}}]}
        }));
        assert_eq!(status_of(&finished).unwrap(), "Succeeded");
        assert!(wanted("terminal").unwrap().contains(&"Succeeded"));

        let evicted = pod(json!({
            "metadata": {"name": "gone", "namespace": "default"},
            "status": {"phase": "Failed", "reason": "Evicted"}
        }));
        assert_eq!(status_of(&evicted).unwrap(), "Failed");
        assert!(wanted("terminal").unwrap().contains(&"Failed"));
    }

    #[test]
    fn a_terminating_pod_is_never_a_target() {
        let dying = pod(json!({
            "metadata": {"name": "dying", "namespace": "default",
                         "deletionTimestamp": "2024-01-01T00:00:00Z"},
            "status": {"phase": "Failed", "containerStatuses": [
                {"name": "c", "ready": false, "restartCount": 0,
                 "state": {"terminated": {"reason": "Error", "exitCode": 1}}}]}
        }));
        assert_eq!(status_of(&dying).unwrap(), "Terminating");
        assert!(!wanted("all").unwrap().contains(&"Terminating"));
    }

    #[test]
    fn a_running_container_protects_the_pod() {
        // One container OOMKilled, one still running: STATUS reads OOMKilled and
        // the set matches, so only the running check keeps the pod alive.
        let mixed = pod(json!({
            "metadata": {"name": "multi", "namespace": "default"},
            "status": {"phase": "Running", "containerStatuses": [
                {"name": "app", "ready": true, "restartCount": 0, "state": {"running": {}}},
                {"name": "batch", "ready": false, "restartCount": 0,
                 "state": {"terminated": {"reason": "OOMKilled", "exitCode": 137}}}]}
        }));
        assert_eq!(status_of(&mixed).unwrap(), "OOMKilled");
        assert!(wanted("terminal").unwrap().contains(&"OOMKilled"));
        assert!(running(&mixed), "a running sibling must protect the pod");

        // Readiness must not matter: an unready but running container is alive.
        let unready = pod(json!({
            "metadata": {"name": "starting", "namespace": "default"},
            "status": {"phase": "Running", "containerStatuses": [
                {"name": "app", "ready": false, "restartCount": 0, "state": {"running": {}}},
                {"name": "batch", "ready": false, "restartCount": 0,
                 "state": {"terminated": {"reason": "OOMKilled", "exitCode": 137}}}]}
        }));
        assert!(running(&unready));
    }

    #[test]
    fn a_native_sidecar_does_not_exempt_a_dead_workload() {
        // A restartable init container keeps running for the pod's lifetime and
        // lands in initContainerStatuses, not containerStatuses. Counting it as
        // "running" would spare a crash-looping pod that an identical pod
        // without a proxy would not be spared, so it is left out on purpose.
        let sidecar = json!({"name": "proxy", "restartPolicy": "Always"});
        let crashing = pod(json!({
            "metadata": {"name": "wedged", "namespace": "default"},
            "spec": {"initContainers": [sidecar]},
            "status": {"phase": "Running",
                "initContainerStatuses": [
                    {"name": "proxy", "ready": true, "restartCount": 0,
                     "state": {"running": {}}}],
                "containerStatuses": [
                    {"name": "app", "ready": false, "restartCount": 7,
                     "state": {"waiting": {"reason": "CrashLoopBackOff"}}}]}
        }));
        assert_eq!(status_of(&crashing).unwrap(), "CrashLoopBackOff");
        assert!(
            !running(&crashing),
            "a proxy must not exempt a dead workload"
        );

        // The benign case needs no special handling: once the application
        // container finishes cleanly the status is no longer in any set.
        let finished = pod(json!({
            "metadata": {"name": "done", "namespace": "default"},
            "spec": {"initContainers": [sidecar]},
            "status": {"phase": "Running",
                "initContainerStatuses": [
                    {"name": "proxy", "ready": true, "restartCount": 0,
                     "state": {"running": {}}}],
                "containerStatuses": [
                    {"name": "app", "ready": false, "restartCount": 0,
                     "state": {"terminated": {"reason": "Completed", "exitCode": 0}}}]}
        }));
        assert_eq!(status_of(&finished).unwrap(), "Running");
        assert!(!wanted("all").unwrap().contains(&"Running"));
    }

    #[test]
    fn a_finished_pod_has_nothing_running() {
        let finished = pod(json!({
            "metadata": {"name": "job", "namespace": "default"},
            "status": {"phase": "Succeeded", "containerStatuses": [
                {"name": "c", "ready": false, "restartCount": 0,
                 "state": {"terminated": {"reason": "Completed", "exitCode": 0}}}]}
        }));
        assert!(!running(&finished));

        let crashing = pod(json!({
            "metadata": {"name": "crash", "namespace": "default"},
            "status": {"phase": "Running", "containerStatuses": [
                {"name": "c", "ready": false, "restartCount": 9,
                 "state": {"waiting": {"reason": "CrashLoopBackOff"}}}]}
        }));
        assert!(!running(&crashing));
        assert_eq!(status_of(&crashing).unwrap(), "CrashLoopBackOff");
    }

    #[test]
    fn tables_cap_their_rows() {
        let rows: Vec<Vec<String>> = (0..MAX_ROWS + 20)
            .map(|i| vec!["default".into(), format!("pod-{i}"), "Failed".into()])
            .collect();
        let section = table("Deleted", &["Namespace", "Pod", "Status"], rows);
        assert_eq!(section["rows"].as_array().unwrap().len(), MAX_ROWS);
        assert!(
            section["lines"][0]
                .as_str()
                .unwrap()
                .starts_with("20 more rows")
        );
    }
}
