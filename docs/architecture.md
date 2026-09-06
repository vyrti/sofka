# Architecture and development

## Module layout

```
main.rs      CLI (clap), terminal lifecycle, the async select! event loop,
             and the --check / --snapshot headless modes.
app.rs       All application state + input handling (a mode state machine:
             Table / Command / Filter / Detail / Logs / FluxMenu /
             PortForwards / Help / Namespaces / …), split into app/*.rs
             (plugins, bookmarks, workspaces, navigation, …). Spawns watch/
             log/port-forward tasks.
k8s.rs       Cluster connect, API discovery, alias registry + group-priority
             resolution, watch-task spawning, namespace listing.
keys.rs      Key-chord parsing + matching (ctrl-/alt-/shift-, function keys)
             for plugin, bookmark, and workspace bindings, with unit tests.
store.rs     In-memory resource store + the Msg enum that watch tasks send to
             the UI (generation-tagged so stale streams are dropped).
columns.rs   Per-kind column definitions and cell extraction from
             DynamicObjects (the "render" layer), with unit tests.
thresholds.rs Configurable RESTARTS/CPU/MEM/utilization coloring bands
             (global + per-resource), compiled from config, with unit tests.
explain.rs   Deterministic "why is this unhealthy?" analysis — pure, turns
             an object + its pods + events into ranked findings, unit-tested.
timeline.rs  Session-local per-object state-change history diffed from the
             watch stream (pure transition logic, unit-tested).
ui.rs        All ratatui rendering: header, table, scrollable views, popups,
             status bar.
theme.rs     Palette + semantic styles, skin resolution.
```

## Data flow

`watcher` tasks push generation-tagged `Msg`s over an `mpsc::UnboundedSender`.
The main `tokio::select!` loop folds them into the `Store`, batching any other
queued updates before it redraws. That same loop also handles terminal input and
a 1s tick (age columns, reaping dead port-forwards). The UI never blocks on the
network.

See [why it's faster](vs-k9s.md#why-its-faster) for the performance-relevant
choices in there.

## Plugin packages

`plugins.rs` loads package manifests and validates input values.
It also controls adapter processes and reads JSON reports.
`app/plugins.rs` connects this code to commands, guardrails, and document views.

Adapters receive a resource snapshot through standard input.
The shared runner serializes that snapshot outside the UI thread.
Tool arguments and tool result formats belong in the adapter.
See [Create a plugin package](plugin-authoring.md).

## Development

```sh
cargo run -- pods            # run against current context
cargo test                   # unit tests (no cluster required)
cargo clippy --all-targets   # lints (clean)
```

## Release

After merging the release-ready changes to `main`, run one of:

```sh
just release-patch
just release-minor
just release-major
```

The recipe switches to a clean, up-to-date `main`, bumps `Cargo.toml` and
`Cargo.lock`, commits and pushes the version bump, then creates the GitHub
Release. The release workflow runs off that published release: it uploads the
platform binaries, publishes to crates.io, and warms the Nix cache.
