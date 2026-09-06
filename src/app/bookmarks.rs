use super::*;

impl App {
    /// Try to trigger a bookmark bound to `key`. Returns whether one matched.
    pub(super) fn try_bookmark_key(&mut self, key: KeyEvent) -> bool {
        let Some(bm) = self
            .bookmarks
            .iter()
            .find(|b| {
                b.key
                    .as_deref()
                    .and_then(|k| crate::keys::KeyChord::parse(k).ok())
                    .is_some_and(|chord| chord.matches(&key))
            })
            .cloned()
        else {
            return false;
        };
        self.apply_bookmark(bm);
        true
    }

    /// Apply a bookmark by name (from the command palette). Returns whether a
    /// bookmark with that name exists.
    pub(super) fn apply_bookmark_named(&mut self, name: &str) -> bool {
        let Some(bm) = self.bookmarks.iter().find(|b| b.name == name).cloned() else {
            return false;
        };
        self.apply_bookmark(bm);
        true
    }

    /// Apply a bookmark. A context change is asynchronous, so the rest of the
    /// bookmark is stashed and applied once the switch lands
    /// ([`Self::apply_pending_bookmark`]).
    pub(super) fn apply_bookmark(&mut self, bm: crate::config::Bookmark) {
        if let Some(ctx) = bm.context.clone()
            && ctx != self.cluster.context
        {
            self.pending_bookmark = Some(bm);
            self.switch_context(ctx);
            return;
        }
        self.apply_bookmark_local(bm);
    }

    /// Apply a bookmark against the current cluster: namespace, resource,
    /// filter, sort, then an optional view.
    pub(super) fn apply_bookmark_local(&mut self, bm: crate::config::Bookmark) {
        if bm.resource.trim().is_empty() {
            self.flash_warn("bookmark has no resource");
            return;
        }
        if self.cluster.resolve(bm.resource.trim()).is_none() {
            self.flash_warn(&format!("No resource matches '{}'", bm.resource));
            return;
        }
        if let Some(error) = crate::filter::parse(bm.filter.as_deref().unwrap_or("")).error() {
            self.flash_warn(&format!("filter: {error}"));
            return;
        }
        self.apply_resource_query(crate::filter::ResourceQuery {
            resource: bm.resource.clone(),
            namespace: bm.namespace.clone(),
            context: None,
            filter: bm.filter.clone().unwrap_or_default(),
        });
        if let Some(sort) = &bm.sort {
            self.apply_sort_spec(sort);
        }
        match bm.view.as_deref() {
            Some("xray") => self.open_xray(),
            Some("pulse") => self.open_pulse(),
            _ => {}
        }
        self.flash = format!("bookmark: {}", bm.name);
        self.flash_err = false;
    }

    /// Apply a stashed bookmark once its context switch has connected.
    pub(super) fn apply_pending_bookmark(&mut self) {
        if let Some(bm) = self.pending_bookmark.take() {
            self.apply_bookmark_local(bm);
        }
    }

    /// Set the active sort from a `COLUMN[:asc|:desc]` spec (bookmark sort).
    fn apply_sort_spec(&mut self, spec: &str) {
        let (name, desc) = match spec.rsplit_once(':') {
            Some((col, "desc")) => (col.trim(), true),
            Some((col, "asc")) => (col.trim(), false),
            _ => (spec.trim(), false),
        };
        let header = name.to_uppercase();
        match self.display_headers().iter().position(|h| *h == header) {
            Some(i) => {
                self.sort_column = Some(i);
                self.sort_desc = desc;
                self.invalidate_rows();
            }
            None => self.flash_warn(&format!("bookmark sort column '{header}' not found")),
        }
    }
}
