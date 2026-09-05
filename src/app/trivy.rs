use super::*;

impl App {
    pub(super) fn open_trivy(&mut self) {
        let Some(executable) = self.trivy_path.clone() else {
            self.flash_warn("Trivy is not installed on PATH");
            return;
        };
        self.set_return_mode();
        if let Some(task) = self.trivy_task.take() {
            task.abort();
        }
        self.trivy_run = self.trivy_run.wrapping_add(1);
        let run = self.trivy_run;
        let generation = self.generation;
        // The display context can be the synthetic "default" sofka shows when
        // the kubeconfig names no current context. Only a real context name is
        // resolvable by Trivy; without one it must infer the config itself.
        let context = self
            .cluster
            .kubectl_context()
            .unwrap_or_default()
            .to_string();
        let namespace = self.namespace.clone();
        let claim = if namespace.is_empty() {
            self.claim_status("Trivy: scanning all namespaces…")
        } else {
            self.claim_status(format!("Trivy: scanning {namespace}…"))
        };
        let tx = self.tx.clone();
        #[cfg(test)]
        let test_timeout = self.trivy_test_timeout;
        self.trivy_task = Some(tokio::spawn(async move {
            #[cfg(not(test))]
            let result = crate::trivy::scan(executable, context, namespace).await;
            #[cfg(test)]
            let result = if let Some(timeout) = test_timeout {
                crate::trivy::scan_with_timeout(executable, context, namespace, timeout).await
            } else {
                crate::trivy::scan(executable, context, namespace).await
            };
            let _ = tx
                .send(Msg::Trivy {
                    generation,
                    run,
                    claim,
                    result,
                })
                .await;
        }));
    }

    /// Refresh the optional command cache. The test-only override avoids
    /// mutating global PATH while the unit suite runs in parallel.
    pub(super) fn rescan_trivy(&mut self) {
        #[cfg(test)]
        let detected = self
            .trivy_test_path
            .as_deref()
            .and_then(crate::trivy::detect_in_path);
        #[cfg(not(test))]
        let detected = crate::trivy::detect();
        self.trivy_path = detected;
    }

    pub(super) fn stop_trivy(&mut self) {
        if let Some(task) = self.trivy_task.take() {
            task.abort();
        }
        self.trivy_run = self.trivy_run.wrapping_add(1);
    }
}
