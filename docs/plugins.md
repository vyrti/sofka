# Plugins, bookmarks, workspaces, forwards

## Plugins

Plugins can use inline configuration or separate packages.
To create a package, see [Create a plugin package](plugin-authoring.md).
Packages support named commands, validated inputs, JSON reports, and managed port-forwards.
Enter `:plugin-cancel` to stop the active plugin run.

`[[plugins]]` assigns an external command to a key or palette command. `key` is a **chord**: a single
character (`"g"`), a modifier combination (`"ctrl-g"`, `"alt-x"`, `"shift-b"`), or
a function or named key (`"f5"`, `"ctrl-f2"`). A built-in key wins over a plugin
on the same chord.

```toml
[[plugins]]
key = "shift-y"
name = "yaml-summary"
command = "kubectl"
args = ["get", "$RESOURCE", "$NAME", "-n", "$NAMESPACE", "-o", "yaml"]
scopes = ["pods", "deployments"]   # omit for all resources
mutating = false          # read-only: still runs under --readonly
output = "popup"          # captured into a scrollable view (see below)

[[plugins]]
key = "ctrl-x"
name = "restart-rollout"
command = "kubectl"
args = ["rollout", "restart", "$RESOURCE/$NAME", "-n", "$NAMESPACE"]
scopes = ["deployments"]
dangerous = true          # confirm (showing the exact command) first
```

- **Placeholders** are substituted as whole arguments, never spliced into a shell
  string: `$NAME`, `$NAMESPACE`/`$NS`, `$CONTEXT`, `$CLUSTER`, `$RESOURCE`
  (plural), `$GROUP`, `$VERSION`, `$KIND`, `$FILTER`.
- **`output`** selects `terminal`, `popup`, `background`, or `report`.
  `terminal` is the default. It suspends the TUI for an interactive command.
  `popup` shows captured text. `background` shows a completion message.
  `report` shows a [JSON report](plugin-authoring.md#report-format).
  Captured modes use `timeout` (`"30s"` by default) and enforce output limits.
- **`palette`** assigns a command name, such as `palette = "scan"` for `:scan`.
  The `key` field is optional when `palette` is present.
- **`target = "context"`** runs once without a selected row.
  The default, `selection`, uses selected or marked rows.
- **`requires`** lists required executables. **`install`** supplies instructions when an executable is absent.
- **`inputs`** defines validated `name=value` arguments.
  See [Inputs](plugin-authoring.md#inputs).
- **`network_load = true`** identifies a load test.
  It requires confirmation and blocks the plugin in read-only mode.
- **`mutating`** (default `true`): read-only mode blocks a mutating plugin. Set
  it to `false` to allow a known read-only one.
- **`confirm`** / **`dangerous`**: prompt before running, showing the exact
  executable and arguments. `dangerous` also shows ⚠.
- **`shell = true`**: opt into `sh -c`. Placeholders still arrive as positional
  parameters (`$1`, `$2`, …), never interpolated into the script.
- **Bulk**: with rows marked (`space`), a `popup` or `background` plugin runs over
  every marked row and reports partial failures. An interactive `terminal` plugin
  can't run over a set and refuses a marked run.

Guardrails match plugin actions with `plugin:<palette>`, or `plugin:<name>` when no palette command exists.

On an invalid value (a bad chord, an unknown `output`, a malformed `timeout`)
sofka disables just that plugin or falls back to the default and shows a warning
in `:config`. Plugins appear in `?` help with their chord and scope.

## Bookmarks

`[[bookmarks]]` are saved navigation commands. One keystroke jumps to a resource
and can switch context or namespace and apply a filter, sort, and view. The key
chord is optional - bookmarks are always in the command palette (`★`, ranked
above resources).

```toml
[[bookmarks]]
key = "shift-1"                          # optional
name = "Prod API failures"
resource = "pods"
context = "prod-eu"                      # optional: switched first
namespace = "checkout"                   # optional; all/* = all namespaces
filter = "status!=Running -l app=api"    # optional, same syntax as `/`
sort = "RESTARTS:desc"                   # optional: COLUMN[:asc|:desc]
view = "xray"                            # optional: xray | pulse
```

## Workspaces

`[[workspaces]]` group several views into a named set for one task - checkout
ops, a cluster upgrade, cert renewal. Open one with a chord or the palette (`▦`).
sofka switches the optional context once and shows the first view. `Tab` /
`Shift-Tab` cycle the other views. You stay in the workspace.

```toml
[[workspaces]]
key = "ctrl-w"
name = "Checkout ops"
context = "prod-eu"          # optional: switched once on open

[[workspaces.views]]
name = "API pods"
resource = "pods"
namespace = "checkout"
filter = "-l app=api"
sort = "RESTARTS:desc"

[[workspaces.views]]
name = "Ingress"
resource = "ingresses"
namespace = "checkout"
```

## Saved forwards

Port-forwards started with `f`/`F` run in the background and are managed with
`:pf`. `[[forwards]]` adds named entries that appear in `:pf` even while stopped
(`⏎` starts one), with optional `autostart` on connect and on matching context
switches.

```toml
[[forwards]]
name = "argocd"
target = "svc/argocd-server"  # kubectl syntax: pod/…, svc/…, deploy/…
namespace = "argocd"
ports = "8080:443"            # LOCAL:REMOTE
autostart = true              # start when sofka connects (default false)
contexts = ["home"]           # optional: only these contexts
```

sofka stops every forward on quit instead of orphaning it.
