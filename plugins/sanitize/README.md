# Sanitize pods

Delete the pods a namespace has finished with: completed jobs, failed and
evicted pods, and — on request — the ones that are wedged.

`:sanitize` in the pods view. The package ships with sofka, so there is nothing
to install and nothing to copy into the configuration directory.

## Requirements

None. The adapter is the sofka binary, invoked as `sofka --plugin-adapter
sanitize`, and it reaches the cluster through the same client the rest of sofka
uses. No Python, no kubectl, no extra runtime on `PATH`.

## Inputs

```text
:sanitize
:sanitize states=stuck
:sanitize dry_run=true
```

| Input     | Values                            | Default    |
| --------- | --------------------------------- | ---------- |
| `states`  | `terminal`, `stuck`, `all`        | `terminal` |
| `dry_run` | `true`, `false`                   | `false`    |

`dry_run=true` reports the pods that match and deletes nothing. It still
requires confirmation, because the package is declared mutating.

## Deletion states

The names are the STATUS values the pods view shows, so what you read in the
table is what `states` selects.

| `states`   | Deletes                                                                  |
| ---------- | ------------------------------------------------------------------------ |
| `terminal` | `Succeeded`, `Failed`, `Error`, `OOMKilled`, `ContainerStatusUnknown`.   |
| `stuck`    | The terminal set, and `CrashLoopBackOff`, `ImagePullBackOff`, `ErrImagePull`. |
| `all`      | The stuck set, and `Pending`.                                            |

`all` is the set k9s sanitizes. It is not the default here, because a `Pending`
pod is usually a pod waiting for a node rather than a pod that failed.

## What it will not delete

- A pod that is already `Terminating`.
- A pod with a running application container, whatever its STATUS reads. A
  multi-container pod reports the reason of the last container that terminated,
  so one can read `OOMKilled` while another still serves traffic. Readiness is
  not part of this check: a container failing its readiness probe, or still
  inside its startup probe, is out of the load balancer and still alive.
  Restartable init containers (native sidecars) do not count. They support the
  workload rather than being it, and counting them would exempt a crash-looping
  pod from `states=stuck` purely for having a proxy injected.
- A pod that was replaced between the scan and the delete. Each delete carries a
  UID precondition, so if a StatefulSet has put a fresh `db-0` behind the name
  that was dead a moment ago, the API rejects the delete and the report counts
  it instead. Pod names are reusable; object identities are not.

## Scope

The scope is the namespace the pods view is on. **In all-namespaces mode it acts
across every namespace**, which for this command is a much larger blast radius
than it sounds.

**The view filter is ignored.** Filtering the table to `web-` and running
`:sanitize` sanitizes the whole namespace, not the rows on screen. Use
`dry_run=true` first if that distinction matters.

## Safety

- **Confirmation** is required: the package is declared `dangerous`, so it
  prompts before running and is marked with ⚠.
- **Read-only mode** blocks it, like every mutating action. `--readonly`,
  `--write`, and a per-context `readonly` setting all apply.
- **Guardrails** match it as `plugin:sanitize`, so it can be denied, given a
  typed confirmation, or capped per context and namespace like any other
  destructive verb. See [Safety](../../docs/safety.md).
- **The action journal** records the run.

```toml
[[guardrails]]
contexts = ["*prod*"]
actions = ["plugin:sanitize"]
deny = true
reason = "Pod cleanup in prod goes through the owning controller."
```

## Replacing it

A user package or an inline `[[plugins]]` entry named `sanitize` takes
precedence over the shipped one, so the behaviour can be replaced without
patching sofka.
