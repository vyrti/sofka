# Filtering and selectors

Press `/` to edit the active filter, Enter to keep it, and Esc to clear it.
Ctrl-U clears the input line. Local terms update as you type; selectors take
effect on Enter, which starts a new watch scoped at the Kubernetes API.
Malformed input shows an error and stays open for editing.

Plain text remains one fuzzy pattern, including spaces. It matches namespace,
name, or an individual displayed column. Structured markers enable these terms:

| Expression                         | Meaning                                            |
| ---------------------------------- | -------------------------------------------------- |
| `!canary`                          | Exclude fuzzy matches                              |
| `-l app=api,env=prod`              | Kubernetes label selector                          |
| `-l app in (api, worker)`          | Kubernetes set selector                            |
| `-l 'app notin (worker),env=prod'` | Quoted selector                                    |
| `-f spec.nodeName=node-3`          | Kubernetes field selector                          |
| `status=CrashLoopBackOff`          | Case-insensitive displayed status                  |
| `cpu>500m`                         | CPU usage in millicores                            |
| `memory>1Gi`                       | Memory usage in bytes, with quantity suffixes      |
| `restarts>=5`                      | Numeric column comparison                          |
| `age<2h`                           | Creation age; seconds, minutes, hours, days, weeks |

Comparisons accept `=`, `==`, `!=`, `>`, `>=`, `<`, and `<=`. `mem` aliases
`memory`; `ns` aliases `namespace`. Other comparison keys name displayed columns.
Well-known paths `metadata.name`, `metadata.namespace`, `spec.nodeName`, and
`status.phase` also work without adding those fields as visible columns.
Quote values with spaces, for example `name='api server'`. Durations may combine
units, such as `1d2h`. CPU and memory use the live metrics snapshot and update
when metrics arrive or disappear. Missing values are unknown, so they do not
match typed comparisons, including negated comparisons; unknown is not zero.
Age queries update as time passes without requiring a resource watch event.

Boolean expressions use spaces or `&&` for AND, `||` for OR, and parentheses
for grouping. AND binds more tightly than OR. `!text` excludes a fuzzy match;
`!(expression)` negates a group. For example:

```text
(status=Pending || restarts>=5) && !canary
!(status=Running && age<2h)
-l app=api (status=Pending || restarts>=5)
```

Selectors scope the API request and must sit outside Boolean groups. To combine
selectors with OR, group the local alternatives as in the last example. A query
such as `-l app=api || worker` is rejected with an explanation because it would
require different API scopes for the alternatives. Repeated selector flags are
joined with commas, preserving Kubernetes AND semantics. Complex selectors with
spaces can be quoted. Boolean groups may nest up to 32 levels.

The title shows `local`, `server`, `server+local`, or `pending ⏎`. Label and field
selectors are sent directly to Kubernetes; field support depends on the resource
and API server. Unsupported selectors produce a watch error. They are never
silently discarded or replaced by an unfiltered download.

Refresh and namespace changes retain the filter. Drill-down keeps the selectors
and combines them with the drill's own scope; local row terms are cleared because
the child has different columns. A selector unsupported by the child API must be
edited or cleared. Esc first clears the child filter, then returns to the parent
with its original filter. Back/forward history restores the root view's filter.

Palette expressions combine resource, namespace, context, and filter:

```text
:pods -n prod --context west /-l app=api status=Running
:pods all /-f spec.nodeName=node-3 cpu>500m
:deployments --namespace prod /!canary
```

Scope options precede `/filter`; everything following the slash uses the row
grammar. Namespace accepts `-n`, `--namespace`, or the existing positional form;
`all` and `*` select all namespaces. Omitted scope options retain the current
scope. When changing context, resource resolution and the first filtered watch
wait for that context to connect. Expressions use the typed scope literally;
the existing `:resource namespace` completion remains available without a filter.
Saved bookmark and workspace filters also scope their first API request.
