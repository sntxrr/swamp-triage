# swamp-triage

A [swamp](https://swamp-club.com) extension repo for investigating **swamp
itself** — why a model or workflow stopped working — using only Deno's built-in
APIs, with no dependencies at all.

## Extensions

### [`@sntxrr/swamp-triage`](./extensions/models/swamp-triage/README.md)

Domain-agnostic failure investigation. An alert names something that broke; this
turns that name into a diagnosis without knowing anything about what the thing
automates.

| Method        | Writes? | What it does                                                     |
| ------------- | ------- | ---------------------------------------------------------------- |
| `investigate` | no      | Resolve a target by name, reconstruct when it broke, classify it |

Every method and workflow run already leaves a `@swamp/method-summary` or
`@swamp/workflow-summary` report behind as versioned model data, written on
failure as well as success — so a target's whole history is on disk before
anyone thinks to look. `investigate` walks it back to the last-success /
first-failure boundary, because the cause is whatever happened between those two
moments.

Given a **workflow** name, it follows the failing step into the model that step
invoked: a workflow summary records *which* step failed but not *why*, so
stopping there reports `detect-drift failed` and omits the actual cause.

| Category      | Means                                                    |
| ------------- | -------------------------------------------------------- |
| `auth`        | The remote answered and rejected the credential          |
| `unreachable` | The remote never answered — network, DNS, or host down   |
| `timeout`     | Connected, but did not finish in time                    |
| `tls`         | Failed at the transport layer, before the request        |
| `rate_limit`  | Refused on volume, not correctness                       |
| `not_found`   | Answered, but the addressed resource is gone             |
| `config`      | Never left swamp — arguments failed validation           |
| `unknown`     | No rule matched; reported verbatim rather than guessed   |
| `none`        | No error recorded; the target is not failing             |

The distinction it exists to make is **`auth` vs `unreachable`**: a controller
answering `403` is up and rejecting your secret (go to the vault); one that never
answers is a network problem (go to the host). Those read almost identically in a
notification and lead in opposite directions.

Read-only — it never invokes the target it investigates, which is what makes it
safe to aim at write-capable models. Full arguments, the workflow wrapper, and
what a finding contains are in the
[extension README](./extensions/models/swamp-triage/README.md).

## Quick start

```bash
# Register an investigator (no credentials, no vault — it reads local state)
swamp model create @sntxrr/swamp-triage/investigation triage

# Investigate whatever the alert named — a model or a workflow
swamp model @sntxrr/swamp-triage/investigation method run investigate triage \
  --input target=nightly-backup

# Read the finding
swamp data get triage nightly-backup --json | jq -r '.content' | jq -r '.summary'
```

A finding reads like this:

```
nightly-backup (workflow) is failing at `backup-host → snapshot`, classified
as **auth**. The remote answered and rejected the credential. The service is
up and reachable; what it holds no longer matches what swamp is sending.

It last worked at 2026-08-04T16:35:14.114Z and first failed at
2026-08-04T17:35:09.460Z; whatever changed between those two moments is the
cause. 1 consecutive failure(s) since.

Next step: Check whether the secret was rotated on the remote, then update
the vault key the model reads and re-run a read-only method to confirm.
```

Wrap it in a workflow to go from alert to notification without opening a
terminal — the target is a workflow input, so one workflow covers every model
and workflow in the repo. See
[Wrapping it in a workflow](./extensions/models/swamp-triage/README.md#wrapping-it-in-a-workflow).

## Development

```bash
~/.swamp/deno/deno check extensions/models/swamp-triage/swamp_triage.ts
~/.swamp/deno/deno test  --allow-read --allow-write \
  extensions/models/swamp-triage/swamp_triage_test.ts
swamp extension quality  extensions/models/swamp-triage/manifest.yaml --json
```

The tests deliberately run **without** `--allow-env`. Nothing here should ever
need environment access, and an added dependency that quietly does would
otherwise fail closed at runtime instead of in CI.

## License

MIT — see [LICENSE.md](./extensions/models/swamp-triage/LICENSE.md).
