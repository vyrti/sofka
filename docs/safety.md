# Safety

## Read-only mode

`readonly = true` in the config disables every mutating action - delete, edit,
scale, shell, mutating plugins, uploads. The `--readonly` and `--write` flags set
the mode for the whole session and win over the config value, including over
per-cluster and per-context overrides, on every `:ctx` switch.

With no flag, switching into a context whose config sets `readonly = true`
enables read-only mode (shown as `[read-only]` in the header). Switching away
restores write mode. A common pattern is a per-context override that makes prod
read-only and repaints it in a light skin - see
[per-context overrides](configuration.md#per-cluster-and-per-context-overrides).

## Guardrails

`[[guardrails]]` turn rules like "never delete in prod", "always confirm drains",
and "no more than 5 at a time" into enforced rules instead of things you have to
remember.

Each rule matches on `contexts`, `namespaces`, `resources`, and `actions` globs
(all optional - an omitted glob matches everything). Rules can set `deny`
(block the action), `confirmation` (require confirmation), and `max_bulk`
(a row limit for one action). The gated `actions` are the destructive verbs sofka
performs directly: `delete`, `force-delete`, `drain`, `restart`, `shell` (exec),
`debug`, `node-debug`, and `transfer` (a file upload into a pod).

sofka combines the restrictions from all matching rules:

- Any matching rule with `deny = true` blocks the action.
- The smallest matching `max_bulk` limit applies. If the number of targets
  exceeds this limit, sofka blocks the action.
- The strongest matching `confirmation` level applies: `type-context-name`
  is stronger than `type-resource-name`, which is stronger than a plain y/N
  confirmation. A rule cannot reduce the action's default confirmation level.
  For a bulk action, `type-resource-name` requires the target count.

Denial takes priority over the bulk limit and confirmation. Rule order does not
change these restrictions. For a denial, sofka shows the `reason` from the last
matching rule with `deny = true`, if that rule has a non-empty reason. Bulk-limit
warnings and confirmation prompts do not show a rule's `reason`.

```toml
[[guardrails]]
contexts = ["*prod*"]
actions = ["delete", "force-delete", "drain"]
deny = true
reason = "Destructive actions on prod go through GitOps, not the TUI."

[[guardrails]]
contexts = ["*prod*"]
actions = ["shell"]
# "type-resource-name" | "type-context-name"; any other value = a plain y/N
confirmation = "type-context-name"
reason = "Confirm the exact pod before shelling into prod."

[[guardrails]]
namespaces = ["kube-system"]
actions = ["delete"]
max_bulk = 1                     # no bulk deletes in kube-system
```

## Managed-resource mutation warnings

Before you edit, delete, scale, or otherwise change an object that Flux, ArgoCD,
(or another controller) owns, sofka warns you that the next reconcile will revert the
change or recreate the object. The point is to send you to the source instead of
fighting the controller.

## Action-aware authorization

`:can-i` runs a `SelfSubjectRulesReview` and shows what you can do in the current
namespace. `:can-i <verb> <resource> [ns]` checks a single action before you try
it. Same answer as `kubectl auth can-i`, inside the TUI.

The empty command-palette browse list hides kinds you cannot `list`. An explicit
search includes every discovered kind because delegated authorizers can return
incomplete rule reviews. The API still enforces access when you open the kind.

## Action journal

`:journal` (or `:audit`) is a session-local in-memory log of every mutating
action you took - the action, the target, the context, the time - newest first.
It records identifiers only, never secret input or decoded values, and never
writes to disk.

## Plugin actions

Guardrails match plugin actions with `plugin:<palette>`.
If a plugin has no palette command, use `plugin:<name>`.
The pattern `plugin:*` matches all plugins.

Read-only mode blocks mutating plugins and plugins with `network_load = true`.
Network-load plugins require confirmation, even when they do not change Kubernetes resources.
See [Plugin safety controls](plugin-authoring.md#safety-controls).
