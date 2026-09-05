use super::*;

impl App {
    pub(super) fn open_popeye(&mut self) {
        let Some(executable) = self.popeye_path.clone() else {
            self.flash_warn("Popeye is not installed on PATH");
            return;
        };
        self.set_return_mode();
        if let Some(task) = self.popeye_task.take() {
            task.abort();
        }
        self.popeye_run = self.popeye_run.wrapping_add(1);
        let run = self.popeye_run;
        let generation = self.generation;
        let context = self.cluster.context.clone();
        let namespace = self.namespace.clone();
        let scope = if namespace.is_empty() {
            "all namespaces".to_string()
        } else {
            namespace.clone()
        };
        let claim = self.claim_status(format!("Popeye: scanning {scope}…"));
        let tx = self.tx.clone();
        self.popeye_task = Some(tokio::spawn(async move {
            let result = crate::popeye::scan(executable, context, namespace).await;
            let _ = tx
                .send(Msg::Popeye {
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
    pub(super) fn rescan_popeye(&mut self) {
        #[cfg(test)]
        let detected = self
            .popeye_test_path
            .as_deref()
            .and_then(crate::popeye::detect_in_path);
        #[cfg(not(test))]
        let detected = crate::popeye::detect();
        self.popeye_path = detected;
    }

    pub(super) fn stop_popeye(&mut self) {
        if let Some(task) = self.popeye_task.take() {
            task.abort();
        }
        self.popeye_run = self.popeye_run.wrapping_add(1);
    }
}
