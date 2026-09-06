use super::*;

impl App {
    /// `:oha [duration] [connections]` — benchmark the selected ingress,
    /// service or pod. The address the object advertises is tried first and a
    /// port-forward is opened only when nothing answers there.
    pub(super) fn open_oha(&mut self, args: &str) {
        let Some(executable) = self.oha_path.clone() else {
            self.flash_warn("oha is not installed on PATH");
            return;
        };
        let options = match crate::oha::parse_options(args) {
            Ok(options) => options,
            Err(error) => {
                self.flash_warn(&error);
                return;
            }
        };
        // Resolve everything off the selection before taking `&mut self`.
        let selection = self.selected_ref().map(|obj| {
            let name = obj.metadata.name.clone().unwrap_or_default();
            let namespace = obj.metadata.namespace.clone().unwrap_or_default();
            let plan = crate::oha::plan(&self.kind_plural, &name, &obj.data, options.port);
            (name, namespace, plan)
        });
        let Some((name, namespace, plan)) = selection else {
            self.flash_warn("select an ingress, service or pod to benchmark");
            return;
        };
        let plan = match plan {
            Ok(plan) => plan,
            Err(error) => {
                self.flash_warn(&error);
                return;
            }
        };
        // Reuse a forward the user already started with `f` rather than
        // opening a second one to the same target.
        let existing_local_port = plan
            .forward
            .as_ref()
            .and_then(|spec| self.existing_forward_port(&namespace, &spec.arg, spec.remote_port));
        let mut forward_argv = self.kubectl_base();
        forward_argv.push("port-forward".into());
        if !namespace.is_empty() {
            forward_argv.push("-n".into());
            forward_argv.push(namespace);
        }

        self.set_return_mode();
        if let Some(task) = self.oha_task.take() {
            task.abort();
        }
        self.oha_run = self.oha_run.wrapping_add(1);
        let run = self.oha_run;
        let generation = self.generation;
        let claim = self.claim_status(format!(
            "oha: benchmarking {name} for {}s…",
            options.duration.as_secs()
        ));
        let tx = self.tx.clone();
        let launch = crate::oha::Launch {
            executable,
            plan,
            options,
            existing_local_port,
            forward_argv,
        };
        #[cfg(test)]
        let test_timeout = self.oha_test_timeout;
        self.oha_task = Some(tokio::spawn(async move {
            #[cfg(not(test))]
            let result = crate::oha::run(launch).await;
            #[cfg(test)]
            let result = if let Some(timeout) = test_timeout {
                crate::oha::run_with_timeout(launch, timeout).await
            } else {
                crate::oha::run(launch).await
            };
            let _ = tx
                .send(Msg::Oha {
                    generation,
                    run,
                    claim,
                    result,
                })
                .await;
        }));
    }

    /// Local port of a live forward already pointing at this target, if any.
    fn existing_forward_port(&self, namespace: &str, target: &str, remote: u16) -> Option<u16> {
        self.port_forwards.iter().find_map(|pf| {
            (pf.ns == namespace && same_forward_target(&pf.target, target))
                .then(|| forward_ports(&pf.ports))
                .flatten()
                .and_then(|(local, forwarded)| (forwarded == remote).then_some(local))
        })
    }

    /// Refresh the optional command cache. The test-only override avoids
    /// mutating global PATH while the unit suite runs in parallel.
    pub(super) fn rescan_oha(&mut self) {
        #[cfg(test)]
        let detected = self
            .oha_test_path
            .as_deref()
            .and_then(crate::oha::detect_in_path);
        #[cfg(not(test))]
        let detected = crate::oha::detect();
        self.oha_path = detected;
    }

    pub(super) fn stop_oha(&mut self) {
        if let Some(task) = self.oha_task.take() {
            task.abort();
        }
        self.oha_run = self.oha_run.wrapping_add(1);
    }
}

/// sofka stores a service forward as `svc/name` but a pod forward as the bare
/// pod name, while the benchmark plan always names a kind.
fn same_forward_target(stored: &str, wanted: &str) -> bool {
    stored == wanted || wanted.strip_prefix("pod/") == Some(stored)
}

/// `LOCAL:REMOTE`, or a single port used for both ends.
fn forward_ports(spec: &str) -> Option<(u16, u16)> {
    match spec.split_once(':') {
        Some((local, remote)) => Some((local.parse().ok()?, remote.parse().ok()?)),
        None => {
            let port = spec.parse().ok()?;
            Some((port, port))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forward_targets_match_across_both_stored_forms() {
        // Services are stored exactly as the plan names them.
        assert!(same_forward_target("svc/web", "svc/web"));
        assert!(!same_forward_target("svc/web", "svc/api"));
        // Pods are stored bare by the `f` prompt but named `pod/x` by the plan.
        assert!(same_forward_target("api-0", "pod/api-0"));
        assert!(!same_forward_target("api-0", "pod/api-1"));
        // A pod and a service of the same name are not the same target.
        assert!(!same_forward_target("web", "svc/web"));
    }

    #[test]
    fn forward_ports_accept_both_kubectl_spellings() {
        assert_eq!(forward_ports("8080:80"), Some((8080, 80)));
        assert_eq!(forward_ports("80"), Some((80, 80)));
        // A kubectl-assigned local port is unknown to us, so it cannot match.
        assert_eq!(forward_ports(":80"), None);
        assert_eq!(forward_ports("nonsense"), None);
    }
}
