# @sntxrr/swamp-triage

Investigate why a swamp model or workflow is failing, without knowing anything
about the domain it automates.

## Why this exists

An alert tells you a scheduled job failed. It does not tell you what broke, when
it broke, or whether to look at the network, the credentials, or your own
definition. Reconstructing that by hand means walking run history, pulling
summary reports, and comparing timestamps — the same sequence of steps every
time, regardless of what the job was actually doing.

All of the raw material is already recorded. Every method run and workflow run
leaves a `@swamp/method-summary` or `@swamp/workflow-summary` report behind as
ordinary versioned model data, and those reports are written on failure as well
as success. The history of any target — what it was doing, whether it worked,
and the exact error when it didn't — is on disk before anyone thinks to look.
This model reads it.

## Why a model and not a report

A report is bound to the execution it runs after. It can render a failure it
witnessed, but it cannot be pointed at an arbitrary past target on demand.
Resolving a target by name at call time is the thing that makes an investigator
generic, and only a method argument can carry that name.

This also explains a constraint worth knowing before building on it: a swamp
workflow's DAG targets are static — in the step schema, `modelName` and
`methodName` are plain strings, and only `inputs` and `globalArgs` accept
`${{ }}` expressions. A workflow cannot choose which model to probe at runtime.
So genericity has to live in a method input, which is exactly what this is.

The corollary: this model reads what previous runs recorded, but cannot *re-run*
a failing target — swamp has no cross-model method invocation. Reproduction
stays a per-target step. In practice this matters less than it sounds, because
the recorded error is the same error a reproduction would produce.

## Methods

### `investigate`

```
swamp model @sntxrr/swamp-triage/investigation method run investigate <name> \
  target=<model-or-workflow-name>
```

| Argument      | Default | Meaning                                              |
| ------------- | ------- | ---------------------------------------------------- |
| `target`      | —       | Name of the model or workflow to investigate         |
| `kind`        | `auto`  | `auto`, `model`, or `workflow`                       |
| `maxVersions` | `60`    | How far back to walk when looking for the last success |

Read-only. It never invokes the target it is investigating.

Writes the finding as an `investigation` resource — carrying the
classification, the last-success/first-failure boundary, the redacted error, and
a `summary` paragraph suitable for a notification body — under two instance
names; see [Where a finding is stored](#where-a-finding-is-stored).

### `recent`

```
swamp model @sntxrr/swamp-triage/investigation method run recent <name> \
  withinHours=24
```

| Argument      | Default | Meaning                                                  |
| ------------- | ------- | -------------------------------------------------------- |
| `withinHours` | `24`    | How far back to look for failed runs (1–720)             |
| `kind`        | `auto`  | `auto`, `model`, or `workflow`                           |
| `limit`       | `20`    | Maximum failures to list; the rest are counted, not lost |

`investigate` needs a name, and an alert does not always carry one: a relayed
notification can arrive with no body, and "what just broke?" has no name in it.
`recent` answers that question first. It lists every model and workflow whose
**most recent** run failed within the window, newest first, each with its
failing step, category and redacted error. Then `investigate` the one that
matters for its full timeline.

Each failure carries its `target` (instance or workflow name) **and**
`targetType` (the model type, or `workflow`). Run history and many alerts name
only a type, and one type can have dozens of instances; `targetType` is what
maps `@acme/ssh/host failed` to the one instance that did, without searching
the model catalog.

It finds summaries with one `context.queryData` query across the whole repo
rather than by walking definition files, so it also sees workflows bundled
inside extensions, which have no file in `workflows/`. A summary's `status`
lives in its JSON content and is not queryable, so each latest summary is read
once; a workflow failure is followed into its step's model from the same
result set, as `investigate` does.

A target that is still failing but last ran before the window, such as a
weekly job broken for days, is counted in `staleFailing` rather than dropped,
so a narrow window cannot make it read as healthy. The `repoDir` global
argument does not apply: `recent` reads the datastore of the repo it runs in.
It needs a swamp runtime that provides `context.queryData`, and says so rather
than returning an empty list when it does not.

Read-only, like `investigate`.

## Categories

The categories are chosen by **where they send you**, not by protocol trivia.

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

The distinction this exists to make is **`auth` vs `unreachable`**. A controller
answering `403` is up, reachable, and rejecting the secret you hold — that sends
you to the vault. A controller that never answers sends you to the network.
Those two read almost identically in a notification and lead in opposite
directions, and guessing wrong wastes the outage.

`unknown` is deliberate. Filing an unrecognised error under a plausible-looking
category would send an operator the wrong way with false confidence; being
visibly unrecognised is the more useful answer.

## The timeline

The useful signal is not *that* something is failing — the alert already said
so. It is the boundary: the last moment it worked and the first moment it
didn't, because the cause is whatever happened in between.

When no success appears anywhere in the examined window, the result carries
`successOutsideWindow: true` rather than reporting the oldest retained failure
as the start. The window is bounded by `maxVersions` as well as by retention, so
the flag means "not found in what we looked at", never "it never worked". A
fabricated start time is worse than an admitted unknown.

## Bundled workflows

Two ship with the extension. They are identical except for the notifier, and
both go from a target name to a notification with nothing else to write:

```bash
swamp workflow run @sntxrr/investigate-apprise --input target=<name>
swamp workflow run @sntxrr/investigate-ntfy    --input target=<name>
```

| Workflow | Needs | Instance name |
| --- | --- | --- |
| `@sntxrr/investigate-apprise` | [`@sntxrr/apprise-notify`](https://swamp-club.com) | `apprise` |
| `@sntxrr/investigate-ntfy` | [`@mgreten/ntfy-notify`](https://swamp-club.com) | `ntfy` |

**Which one:** prefer Apprise if you already run it — a single endpoint fans out
to ntfy *plus* Matrix, Discord, email and 100+ others, so it picks a gateway
rather than a destination. Use the ntfy workflow when you want to post straight
to ntfy and run no Apprise server.

**Why two workflows and not one with a switch:** a workflow step's
`modelIdOrName` and `methodName` are plain strings, not expressions — only
`inputs` and `guard` accept `${{ }}`. The two notifiers differ in both (`notify`
with a `body` argument vs `send` with a `message` argument), so no single step
can serve both. Adding a third transport is another workflow file, not a code
change.

Both are read-only, and both are deliberately **untriggered** — this is what you
reach for once something has already failed.

### The quiet-when-healthy gate

Notification is gated on the *finding*, not on run status, so investigating a
healthy target completes successfully and sends nothing:

```yaml
guard: >-
  ${{ !inputs.notify ||
  !data.latest('triage', 'current').attributes.failing }}
```

A `guard` is a CEL predicate evaluated before the step, where **truthy means
skip**. It is the only workflow-level way to branch on step *output* —
`dependsOn` conditions are status-based (`succeeded`/`failed`/…) and cannot
express a predicate. The gate lives here rather than in a notifier's own
arguments so it stays identical across transports; `ntfy-notify` has no gating
argument at all, and `send` always sends.

## Wrapping it in your own workflow

The model is the generic half. A workflow around it turns an alert into a
notification without anyone opening a terminal — the target comes in as a
workflow input, so one workflow covers every model and workflow in the repo:

```yaml
inputs:
  properties:
    target: { type: string }
    notify: { type: boolean, default: true }
  required: [target]
jobs:
  - name: investigate
    steps:
      - name: collect
        task:
          type: model_method
          modelIdOrName: triage
          methodName: investigate
          inputs:
            target: ${{ inputs.target }}
  - name: report
    steps:
      - name: notify-finding
        task:
          type: model_method
          modelIdOrName: apprise      # ← your notifier, not this package's
          methodName: notify
          inputs:
            title: >-
              ${{ "Investigation: " + inputs.target + " (" +
              data.latest('triage', 'current').attributes.category + ")" }}
            body: ${{ data.latest('triage', 'current').attributes.summary }}
            # Gate on the finding, not run status: a healthy target stays quiet.
            guard: >-
              ${{ !inputs.notify ||
              !data.latest('triage', 'current').attributes.failing }}
        allowFailure: true
    dependsOn:
      - job: investigate
        condition: { type: succeeded }
```

Swap `notifier` for whatever you already run. The investigating half is the
reusable part; the alerting half is yours.

### Adding durability with an outbox

The bundled workflows notify directly: if the transport is down, the finding is
still recorded but the notification is simply lost (the step is
`allowFailure: true`, so a dead notifier never masks a good finding). If you
want delivery to survive that, put
[`@mgreten/notification-outbox`](https://swamp-club.com) in front of it — a
durable, deduplicating ledger.

Be clear about what it is, though: it **performs no transport I/O**.
`enqueueNotification` writes a record; `drainNotifications` takes *"the
transport results the caller obtained"*. It sits in front of a notifier, it does
not replace one — so you still need an apprise or ntfy step, and the shape
becomes:

```
investigate → enqueueNotification → <your notifier> → drainNotifications
```

What you gain is dedup (an alert storm collapses to one record per
`workItem`+`event`+`era`) and durable retry state. What it costs is two extra
steps and some mapping work: `workItem` must match `^[a-zA-Z0-9][a-zA-Z0-9_-]*$`,
so a target named with a `/` or `.` needs sanitising first; `event` is an enum of
`approval-needed | failed | completed`, so a triage category maps onto `failed`
or `completed` rather than travelling as itself; and `era` wants a stable
per-run token you supply as a workflow input.

Worth it for a noisy fleet where the same failure would otherwise page you
hourly. Overkill for a handful of watchers, which is why it is not bundled.

## Where a finding is stored

Each `investigate` run writes the same finding to two instances:

| Instance | For |
| --- | --- |
| `current` | The stable handle to reference: `data.latest('triage', 'current')` |
| percent-encoded target name | Per-target history, comparable across runs |

Reference `current` from a workflow. Deriving the instance from the target name
does not work in general: swamp rejects `/` in a data name, and a workflow
bundled in an extension is *required* to be collective-scoped — so
`@acme/nightly-backup` could not be stored at all. The per-target instance
percent-encodes it (`@acme%2Fnightly-backup`) rather than folding the slash to
a dash, which would map `@acme/thing` and `@acme-thing` onto one instance and
interleave two unrelated targets' histories.

Concurrent investigations race on `current`; read the per-target instance when
that matters.

`recent` writes a `recent` resource to a single instance, also named `recent`,
overwritten on every run: `data.latest('triage', 'recent')`. Its errors are
redacted by the same rules below.

`current` and `recent` are reserved. A target with exactly one of those names
has its per-target instance's first character encoded too (`%72ecent`), so
investigating it cannot overwrite the handle a workflow reads.

## What a finding contains

The finding republishes the error string the target's own summary report
recorded. That is the point — a paraphrased error is not diagnosable — but the
text is about to travel further than it was written to go, into a chat channel
or a phone.

Swamp already redacts model global arguments in those reports (a vaulted
password shows as `***`). What it cannot redact is a secret an upstream model
wrote into the *body* of its own error message. So this model redacts too,
before the finding is written:

| Rule | Catches |
| --- | --- |
| `private-key` | Whole `-----BEGIN … PRIVATE KEY-----` blocks |
| `jwt` | `eyJ…` three-part tokens |
| `url-credentials` | `https://user:pass@host` |
| `authorization-header` | `Authorization: Bearer …` |
| `provider-token` | `AKIA…`, `ghp_…`, `github_pat_…`, `xox[baprs]-…`, `sk-…` |
| `keyed-value` | `password=…`, `"api_key": "…"`, `token: …` and kin |

Each rule keeps the key or scheme and blanks only the value, so `token=abc123`
becomes `token=[redacted]` — still obviously a token problem, no longer a leaked
token. The finding reports `redactions` (a count) and `redactedKinds`, so a
reader can tell what was removed rather than wondering.

Redaction is deliberately **structural, not lexical**: it redacts
`password=<value>`, never the word "password". The controller error that
motivated this model reads `Invalid username or password` and carries no value
at all — blanking that phrase would destroy the single most diagnostic sentence
in the finding while protecting nothing. Classification also runs on the
original text *before* redaction, so redaction can never eat the evidence a
classifier rule matches on and silently downgrade a known failure to `unknown`.

It is a net, not a guarantee — a secret in a shape no rule recognises still
travels. It narrows the exposure rather than closing it.

Nothing else in a finding is sensitive: `definitionPath` is stored
repo-relative, so a finding never carries the investigating host's directory
layout.

## Dependencies

None. Deliberately.

Reading three top-level scalars (`id`, `name`, `type`) out of a swamp-generated
definition does not need a YAML parser, and the obvious one reaches for
`process.env`, which throws under a sandbox with no env access. That error is
indistinguishable from "this file is not valid YAML", so every definition would
have silently failed to resolve and the model would have reported *target not
found* for a repo full of targets — the exact failure mode it exists to prevent.

The hand reader only considers column-zero `key: value` lines, so indented
block-scalar content cannot be mistaken for a field. It is tested against decoy
`name:`/`id:` lines inside a `description: >-` block, and was verified
field-for-field against `npm:yaml` on real definition files.

## Prior art

[`@mgreten/software-factory-run-audit`](https://swamp-club.com) reconstructs
runs deterministically from recorded run data using the same technique, scoped
to `@swamp/software-factory` work items. This generalizes it to any model or
workflow.

`@jentz/triage-snapshot` and `@webframp/sre` cover adjacent ground as reports —
rendering triage artifacts a workflow already collected, and health-checking
what is up right now, respectively. Neither resolves a target by name after the
fact, which is the gap this fills.

## License

MIT
