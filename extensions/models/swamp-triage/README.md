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

## Method

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

Writes one `investigation` resource carrying the classification, the
last-success/first-failure boundary, the verbatim error, and a `summary`
paragraph suitable for a notification body.

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

When no success appears anywhere in the retained history, the result carries
`successOutsideRetention: true` rather than reporting the oldest retained
failure as the start. A fabricated start time is worse than an admitted unknown.

## Wrapping it in a workflow

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
              data.latest('triage', inputs.target).attributes.category + ")" }}
            body: ${{ data.latest('triage', inputs.target).attributes.summary }}
            # Gate on the finding, not run status: a healthy target stays quiet.
            when: >-
              ${{ inputs.notify &&
              data.latest('triage', inputs.target).attributes.failing }}
        allowFailure: true
    dependsOn:
      - job: investigate
        condition: { type: succeeded }
```

This is documented rather than bundled on purpose: the notify step names a
model instance (`apprise`) that is specific to one operator's setup. Shipping
it would hard-code a notifier nobody else has. The investigating half is the
reusable part; wire the alerting half to whatever you already run.

Note the `when` gate lives in the notifier's own arguments rather than in a step
condition — swamp step conditions are status-based and cannot express a
predicate over step output.

## What a finding contains

The finding republishes the **verbatim error string** the target's own summary
report recorded. That is the point — a paraphrased error is not diagnosable —
but it is worth knowing before wiring the `summary` into a chat channel.

Swamp already redacts model global arguments in those reports (a vaulted
password shows as `***`). What it cannot redact is a secret an upstream model
wrote into the *text* of its own error message. If one of your models does that,
this will carry it into whatever the notification step sends. That is a property
of the upstream error, not something this model can detect — suppressing the
recorded error would defeat the tool. Worth a look at your own models' error
paths before pointing a public channel at it.

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
