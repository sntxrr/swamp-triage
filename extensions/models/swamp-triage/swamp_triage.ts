// @sntxrr/swamp-triage/investigation
//
// Investigate why a swamp model or workflow is failing, without knowing
// anything about the domain it automates.
//
// Every method run and workflow run leaves a `@swamp/method-summary` or
// `@swamp/workflow-summary` report behind as ordinary versioned model data.
// Those reports are written on failure as well as success, so the full history
// of a target -- what it was doing, whether it worked, and the exact error when
// it didn't -- is already on disk. Nothing else needs to be instrumented.
//
// This model reads that history for a target named at call time, walks it back
// to the boundary where the target stopped working, and classifies the error
// into a category with a concrete next step. It is read-only: it never invokes
// the failing target, only reads what previous runs recorded.
//
// Why a model and not a report: a report is bound to the execution it runs
// after, so it can render a failure it witnessed but cannot be pointed at an
// arbitrary past target. Resolving a target by name at call time is what makes
// this generic, and only a method argument can carry that.
//
// Prior art: @mgreten/software-factory-run-audit reconstructs runs
// deterministically from recorded run data the same way, but is scoped to
// @swamp/software-factory work items. This generalizes the technique to any
// model or workflow.

import { z } from "npm:zod@4";

/* ------------------------------------------------------------------ *
 * Error classification
 *
 * The categories are chosen by what they imply about where to look, not
 * by protocol trivia. The distinction that matters most in practice is
 * auth vs unreachable: a remote that answers with 403 is healthy and
 * reachable and is rejecting the credential, which sends you to the
 * vault. A remote that never answers sends you to the network. Those
 * read almost identically in a notification and lead opposite ways.
 * ------------------------------------------------------------------ */

/** A category of failure, and where it points the operator. */
export interface Classification {
  /** Stable machine-readable category slug. */
  category: string;
  /** Whether a rule matched, or this is the residual bucket. */
  matched: boolean;
  /** What the category means for this target. */
  meaning: string;
  /** The single most useful next action. */
  nextStep: string;
}

interface Rule {
  category: string;
  /** Matched case-insensitively against the recorded error text. */
  patterns: RegExp[];
  meaning: string;
  nextStep: string;
}

const UNREACHABLE_MEANING =
  "The remote never answered. This is a network, DNS or host-down " +
  "problem, not a credential problem.";
const UNREACHABLE_NEXT_STEP =
  "Confirm the host is up and routable from wherever swamp runs, " +
  "including any tailnet or VPN the address depends on.";

/**
 * Ordered classification rules; the first match wins.
 *
 * Order matters where categories overlap. Auth precedes the generic HTTP
 * buckets because a 403 carrying "invalid credentials" is an auth problem
 * first and an HTTP status second. Generic wrappers go last, so any specific
 * cause they carry is matched first.
 */
const RULES: Rule[] = [
  {
    // Swamp's own wording when a `${{ }}` expression in a definition fails to
    // evaluate. First, because the expression error quotes whatever it was
    // evaluating -- "No such key", a 404 in a data value -- and those words
    // would otherwise send the operator to the remote. The step never ran;
    // the definition is wrong.
    category: "config",
    patterns: [/\binvalid expression\b/i, /ambiguous data\.latest\(\)/i],
    meaning: "An expression in the definition failed to evaluate, so the " +
      "step never ran. The remote is not involved: the definition reads " +
      "data that is missing, ambiguous or shaped differently than it expects.",
    nextStep: "Open the definition the step belongs to and fix the " +
      "expression the error quotes -- for an ambiguous `data.latest()`, name " +
      "the specific data item instead of the spec.",
  },
  {
    category: "auth",
    patterns: [
      /\b401\b/,
      /\b403\b/,
      /invalid[ _-]?(username|password|credential)/i,
      /authentication[ _-]?failed/i,
      /unauthorized/i,
      /forbidden/i,
      /permission denied/i,
      /access denied/i,
      /\bmfa\b/i,
      /token (has )?expired/i,
      /invalid[ _-]?(token|api[ _-]?key|signature)/i,
      /signature.*(mismatch|invalid)/i,
    ],
    meaning:
      "The remote answered and rejected the credential. The service is up " +
      "and reachable; what it holds no longer matches what swamp is sending.",
    nextStep:
      "Check whether the secret was rotated on the remote, then update the " +
      "vault key the model reads and re-run a read-only method to confirm.",
  },
  {
    category: "unreachable",
    patterns: [
      /ECONNREFUSED/i,
      /EHOSTUNREACH/i,
      /ENETUNREACH/i,
      /ENOTFOUND/i,
      /EAI_AGAIN/i,
      /connection refused/i,
      /network is unreachable/i,
      /no route to host/i,
      /dns/i,
      /getaddrinfo/i,
    ],
    meaning: UNREACHABLE_MEANING,
    nextStep: UNREACHABLE_NEXT_STEP,
  },
  {
    category: "timeout",
    patterns: [
      /ETIMEDOUT/i,
      /timed? ?out/i,
      /deadline exceeded/i,
      /\baborted\b/i,
    ],
    meaning: "The remote accepted the connection but did not finish in time. " +
      "Often load or a hung dependency rather than misconfiguration.",
    nextStep:
      "Re-run once to see whether it is transient, and check the remote's " +
      "own health before changing any definition.",
  },
  {
    category: "tls",
    patterns: [
      /certificate/i,
      /\bssl\b/i,
      /\btls\b/i,
      /self[ -]?signed/i,
      /CERT_/,
      /x509/i,
    ],
    meaning:
      "The transport layer failed before the request was made. Usually an " +
      "expired, self-signed or hostname-mismatched certificate.",
    nextStep:
      "Check the remote's certificate expiry and subject against the host " +
      "the model is configured to reach.",
  },
  {
    category: "rate_limit",
    patterns: [/\b429\b/, /rate[ _-]?limit/i, /throttl/i, /too many requests/i],
    meaning: "The remote is refusing on volume, not on correctness. The " +
      "credentials and configuration are fine.",
    nextStep:
      "Reduce the schedule frequency or fan-out for this target; re-running " +
      "immediately will usually fail the same way.",
  },
  {
    category: "not_found",
    patterns: [
      /\b404\b/,
      /not found/i,
      /does not exist/i,
      /no such/i,
      /NoSuchEntity/,
    ],
    meaning:
      "The remote answered but the thing being addressed is gone. Something " +
      "was renamed or deleted out from under the definition.",
    nextStep:
      "Verify the resource still exists on the remote, then reconcile the " +
      "model definition against what is actually there.",
  },
  {
    // Swamp's own wording when a call's arguments fail the method's schema.
    // Ahead of `config`, which would match "validation failed" and send the
    // operator to the definition -- but the definition holds no method
    // arguments. The call was wrong, so look at whoever made it.
    category: "caller_args",
    patterns: [/method arguments validation failed/i],
    meaning: "The call was rejected before it ran: the arguments passed to " +
      "this method failed its schema. The definition and the remote are not " +
      "involved -- whoever made the call passed a bad value.",
    nextStep: "Find the caller -- a workflow step's inputs, a cron line, or " +
      "an agent's ad-hoc call -- and fix the argument it passes. A success " +
      "seconds later usually means the caller already corrected itself.",
  },
  {
    category: "config",
    patterns: [
      /validation[ _-]?failed/i,
      /unknown input/i,
      /invalid input/i,
      /schema/i,
      /required/i,
      /missing.*(argument|field|parameter)/i,
    ],
    meaning:
      "The call never left swamp -- the arguments failed validation. This " +
      "is a definition or input problem, not a remote problem.",
    nextStep:
      "Compare the inputs the run recorded against the method's argument " +
      "schema with `swamp model type describe`.",
  },
  {
    // `fetch` throws `TypeError: fetch failed` when no connection was made,
    // and puts the reason -- if any -- beside it. Last, so that reason wins:
    // `fetch failed ... ETIMEDOUT` is a timeout, a bare `fetch failed` is not.
    category: "unreachable",
    patterns: [/fetch failed/i],
    meaning: UNREACHABLE_MEANING,
    nextStep: UNREACHABLE_NEXT_STEP,
  },
];

/* ------------------------------------------------------------------ *
 * Secret redaction
 *
 * A finding republishes the target's error text, and that text is
 * about to travel further than it was written to go -- into a chat
 * channel, a phone. Swamp already redacts a model's declared global
 * arguments, so a vaulted password shows as ***. What it cannot redact
 * is a secret an upstream model put in the *body* of its own error.
 *
 * Every rule below redacts a value it can identify structurally, and
 * leaves the surrounding text intact so the error stays diagnosable.
 * Redaction is deliberately conservative: a missed secret is bad, but a
 * mangled error the operator cannot act on defeats the whole tool.
 * ------------------------------------------------------------------ */

/** The outcome of redacting one error string. */
export interface Redaction {
  /** The text with identified secret values replaced. */
  text: string;
  /** How many values were replaced. */
  count: number;
  /** Which rules fired, for the operator to judge what was removed. */
  kinds: string[];
}

interface RedactRule {
  kind: string;
  pattern: RegExp;
  /** Replacement, using capture groups to keep the identifying context. */
  replace: string;
}

/**
 * Ordered redaction rules.
 *
 * Each keeps the key or scheme that identifies *what* was removed and blanks
 * only the value, so `token=abc123` becomes `token=[redacted]` -- still
 * obviously a token problem, no longer a leaked token.
 */
const REDACT_RULES: RedactRule[] = [
  {
    // Whole PEM blocks. First, because their body would otherwise be chewed
    // on by the narrower rules below.
    kind: "private-key",
    pattern:
      /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
    replace: "[redacted:private-key]",
  },
  {
    kind: "jwt",
    pattern: /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{4,}/g,
    replace: "[redacted:jwt]",
  },
  {
    kind: "url-credentials",
    pattern: /([a-z][a-z0-9+.-]*:\/\/)([^\s:@/]+):([^\s@/]+)@/gi,
    replace: "$1$2:[redacted]@",
  },
  {
    kind: "authorization-header",
    pattern: /\b(authorization\s*[:=]\s*)(?:(bearer|basic|token)\s+)?\S+/gi,
    replace: "$1$2 [redacted]",
  },
  {
    // Provider-shaped tokens, which are recognisable on their own.
    kind: "provider-token",
    pattern:
      /\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9]{20,})\b/g,
    replace: "[redacted:token]",
  },
  {
    // Quoted JSON form: "password": "hunter2"
    kind: "keyed-value",
    pattern:
      /(["'](?:password|passwd|pwd|secret|token|api[-_]?key|apikey|access[-_]?key|private[-_]?key|credential|auth)["']\s*:\s*)["'][^"']*["']/gi,
    replace: '$1"[redacted]"',
  },
  {
    // Bare form: password=hunter2, token: abc123, api_key => xyz
    kind: "keyed-value",
    pattern:
      /\b(password|passwd|pwd|secret|token|api[-_]?key|apikey|access[-_]?key|private[-_]?key|credential)\b(\s*[:=]+\s*)(["']?)[^\s"'&,;)}\]]+\3/gi,
    replace: "$1$2[redacted]",
  },
];

/**
 * Replace identifiable secret values in an error string.
 *
 * Deliberately structural: it redacts `password=<value>`, not the word
 * "password". The controller error that motivated this model reads `Invalid
 * username or password` and carries no value at all -- redacting that phrase
 * would destroy the single most diagnostic sentence in the finding while
 * protecting nothing.
 *
 * @param text Error text as recorded by the target's summary report.
 * @returns The redacted text plus what was removed.
 */
export function redactSecrets(text: string | null | undefined): Redaction {
  let out = text ?? "";
  let count = 0;
  const kinds: string[] = [];
  for (const rule of REDACT_RULES) {
    // Fresh lastIndex per use; these are global regexes.
    rule.pattern.lastIndex = 0;
    const hits = out.match(rule.pattern);
    if (!hits || hits.length === 0) continue;
    count += hits.length;
    if (!kinds.includes(rule.kind)) kinds.push(rule.kind);
    out = out.replace(rule.pattern, rule.replace);
  }
  return { text: out, count, kinds };
}

/**
 * Classify a recorded error string into an actionable category.
 *
 * Falls back to an explicit `unknown` classification rather than guessing, so
 * an unrecognised error is visibly unrecognised instead of being filed under a
 * plausible-looking category that sends the operator the wrong way.
 *
 * A missing error means two different things depending on whether the run
 * failed, so the caller says which. A target that did not fail is `none`; one
 * that failed with no recoverable text is `unrecorded` -- distinct from
 * `unknown`, which means there was text and no rule matched it.
 *
 * @param error The error text recorded by the summary report.
 * @param failed Whether the run the error belongs to failed.
 * @returns The matched category with its meaning and next step.
 */
export function classifyError(
  error: string | null | undefined,
  failed = false,
): Classification {
  const text = (error ?? "").trim();
  if (text === "" && failed) {
    return {
      category: "unrecorded",
      matched: false,
      meaning: "The run failed, but no error text was recorded or could be " +
        "recovered -- typically an assert step, or a workflow run that " +
        "recorded no error for its failed step and whose step model has " +
        "succeeded since.",
      nextStep: "Open the failing run's own summary with `swamp workflow " +
        "history logs` or `swamp report get`; the cause is there, not here.",
    };
  }
  if (text === "") {
    return {
      category: "none",
      matched: false,
      meaning: "No error was recorded for this target.",
      nextStep: "Nothing to investigate; the target's last run did not fail.",
    };
  }
  for (const rule of RULES) {
    if (rule.patterns.some((p) => p.test(text))) {
      return {
        category: rule.category,
        matched: true,
        meaning: rule.meaning,
        nextStep: rule.nextStep,
      };
    }
  }
  return {
    category: "unknown",
    matched: false,
    meaning:
      "The error did not match any known category. It is reported verbatim " +
      "rather than guessed at.",
    nextStep: "Read the full error below and the target's own logs with " +
      "`swamp workflow history logs` or `swamp report get`.",
  };
}

/* ------------------------------------------------------------------ *
 * Timeline reconstruction
 * ------------------------------------------------------------------ */

/** One recorded run, as read back from a summary report version. */
export interface RunPoint {
  version: number;
  createdAt: string;
  status: string;
  /** Absent for workflow-scope reports. */
  methodName?: string | null;
  error?: string | null;
}

/** Where a target crossed from working to broken. */
export interface Timeline {
  /** Status of the most recent recorded run. */
  currentStatus: string;
  /** How many consecutive failures at the head of the history. */
  consecutiveFailures: number;
  /** The oldest failure in the current unbroken run of failures. */
  firstFailure: RunPoint | null;
  /** The most recent run that succeeded, if one is still retained. */
  lastSuccess: RunPoint | null;
  /**
   * True when the examined window ended without a success. The window is
   * bounded by `maxVersions` and by retention, so this means "not found in
   * what we looked at" -- not "the target never worked".
   */
  successOutsideWindow: boolean;
  /** How many recorded runs were examined. */
  examined: number;
}

/**
 * Reconstruct the working-to-broken boundary from recorded runs.
 *
 * Takes points newest-first. The useful signal is not "it is failing" -- the
 * alert already said that -- but the last moment it worked and the first
 * moment it did not, because the cause is whatever happened between them.
 *
 * A target that has failed for its entire retained history returns
 * `successOutsideWindow`, which is materially different from "it never
 * worked" and must not be reported as a known-good boundary. The window is
 * bounded by the caller's `maxVersions` as well as by retention, so the flag
 * means "not found in what we looked at", never "does not exist".
 *
 * @param points Recorded runs, ordered newest first.
 * @returns The reconstructed boundary.
 */
export function reconstructTimeline(points: RunPoint[]): Timeline {
  if (points.length === 0) {
    return {
      currentStatus: "unknown",
      consecutiveFailures: 0,
      firstFailure: null,
      lastSuccess: null,
      successOutsideWindow: false,
      examined: 0,
    };
  }

  const failed = (p: RunPoint) => p.status !== "succeeded";

  let consecutiveFailures = 0;
  let firstFailure: RunPoint | null = null;
  for (const p of points) {
    if (!failed(p)) break;
    consecutiveFailures++;
    firstFailure = p;
  }

  const lastSuccess = points.find((p) => !failed(p)) ?? null;

  return {
    currentStatus: points[0].status,
    consecutiveFailures,
    firstFailure,
    lastSuccess,
    // Only meaningful when the head is actually a failure run.
    successOutsideWindow: lastSuccess === null && consecutiveFailures > 0,
    examined: points.length,
  };
}

/* ------------------------------------------------------------------ *
 * Target resolution
 *
 * dataRepository is addressed by (type, id), but an operator investigating
 * an alert has a name. Model and workflow definitions are plain YAML in the
 * repo, so the mapping is read from there rather than guessed.
 * ------------------------------------------------------------------ */

/** A resolved investigation target. */
export interface ResolvedTarget {
  name: string;
  /** "model" or "workflow". */
  kind: string;
  /** Data-repository type key: the model type, or literal "workflow". */
  type: string;
  id: string;
  /** Repo-relative path of the definition that supplied the mapping. */
  definitionPath: string;
  /** A workflow's `trigger.schedule` cron, or null when it has none. */
  schedule: string | null;
  /** The definition's `tags`, e.g. a placement tag naming where it runs. */
  tags: Record<string, string>;
  /** The definition's `description`, folded to one line; "" when absent. */
  description?: string;
}

/**
 * Read the top-level scalar fields of a swamp definition file.
 *
 * Deliberately not a YAML library. Only three fields are ever needed -- `id`,
 * `name` and `type` -- and every one is a plain scalar at column zero in a
 * swamp-generated definition. A full parser bought nothing for that and cost a
 * dependency that reaches for `process.env`, which throws under a sandbox
 * without env access; the resulting error is indistinguishable from "this file
 * is not valid YAML", so every definition would silently fail to resolve and
 * the model would report "target not found" for a repo full of targets.
 *
 * Only column-zero `key: value` lines are considered, so indented content --
 * including every line of a `description: >-` block scalar, which must be
 * indented deeper than its key -- is skipped rather than mistaken for a field.
 * A key whose value opens a block scalar (`>` or `|`) is skipped for the same
 * reason: those are never the fields wanted here.
 *
 * @param text Raw file contents.
 * @returns The top-level scalar fields found.
 */
export function readTopLevelScalars(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split("\n")) {
    // Indented => nested or block-scalar content, never a top-level field.
    if (/^\s/.test(line)) continue;
    if (line.trimEnd() === "" || line.startsWith("#")) continue;
    const m = /^([A-Za-z_][A-Za-z0-9_-]*):[ \t]*(.*)$/.exec(line);
    if (!m) continue;
    const value = scalarValue(m[2]);
    if (value !== null) out[m[1]] = value;
  }
  return out;
}

/**
 * Normalize the value half of a `key: value` line, or null when it is empty
 * or opens a block scalar.
 */
function scalarValue(raw: string): string | null {
  let value = raw.trim();
  if (value === "" || value.startsWith(">") || value.startsWith("|")) {
    return null;
  }
  // Strip an inline comment only when the value is not quoted.
  if (!/^["']/.test(value)) value = value.replace(/\s+#.*$/, "").trim();
  // Unwrap matching surrounding quotes.
  const q = /^(["'])([\s\S]*)\1$/.exec(value);
  if (q) value = q[2];
  return value === "" ? null : value;
}

/**
 * Read the scalar children of one top-level mapping, e.g. `trigger` or `tags`.
 *
 * The same deliberate non-parser as `readTopLevelScalars`, one level down:
 * only lines at the mapping's first child indentation count, so a grandchild
 * or the body of a block scalar cannot be mistaken for a child. The mapping
 * ends at the next column-zero line.
 *
 * @param text Raw file contents.
 * @param parent Top-level key whose children to read.
 * @returns The child scalar fields found; empty when the key is absent.
 */
export function readNestedScalars(
  text: string,
  parent: string,
): Record<string, string> {
  const out: Record<string, string> = {};
  let inside = false;
  let indent: string | null = null;
  for (const line of text.split("\n")) {
    if (line.trimEnd() === "" || /^\s*#/.test(line)) continue;
    if (!/^\s/.test(line)) {
      // A column-zero line opens or closes the mapping.
      inside = new RegExp(`^${parent}:\\s*(#.*)?$`).test(line.trimEnd());
      indent = null;
      continue;
    }
    if (!inside) continue;
    const lead = /^(\s+)/.exec(line)![1];
    if (indent === null) indent = lead;
    if (lead !== indent) continue;
    const m = /^\s+([A-Za-z_][A-Za-z0-9_-]*):[ \t]*(.*)$/.exec(line);
    if (!m) continue;
    const value = scalarValue(m[2]);
    if (value !== null) out[m[1]] = value;
  }
  return out;
}

/**
 * Rank definition names by how well they match a name that resolved to none.
 *
 * An agent guessing at a target from an alert's wording gets the name nearly
 * right -- `nightly-dump` for `archive-nightly-dump`. A flat "not found" sends
 * it guessing again; each wrong guess is another failed run. Token overlap
 * (Jaccard over `-`, `_`, `/`, `.`, `@` separated words) plus a bonus when one
 * name contains the other is enough to put the intended name first, and is
 * predictable enough to explain.
 *
 * @param query The name that was not found.
 * @param candidates Every definition, as `listDefinitions` returns them.
 * @param limit Most suggestions to return.
 * @returns Best matches first; never a candidate sharing nothing with query.
 */
export function rankNames(
  query: string,
  candidates: { name: string; kind: string }[],
  limit = 3,
): { name: string; kind: string; score: number }[] {
  const words = (s: string) =>
    new Set(s.toLowerCase().split(/[^a-z0-9]+/).filter((w) => w !== ""));
  const q = words(query);
  const needle = query.toLowerCase();
  const scored: { name: string; kind: string; score: number }[] = [];
  for (const c of candidates) {
    const w = words(c.name);
    const shared = [...q].filter((x) => w.has(x)).length;
    const union = new Set([...q, ...w]).size;
    const hay = c.name.toLowerCase();
    const contains = needle !== "" &&
      (hay.includes(needle) || needle.includes(hay));
    const score = (union === 0 ? 0 : shared / union) + (contains ? 0.5 : 0);
    if (score > 0) scored.push({ ...c, score: Math.round(score * 100) / 100 });
  }
  scored.sort((a, b) => b.score - a.score || a.name.localeCompare(b.name));
  return scored.slice(0, limit);
}

/**
 * Read a definition's top-level `description`, folded to one line.
 *
 * The same deliberate non-parser as `readTopLevelScalars`, extended to the
 * one block scalar worth reading: a `description: >-` or `|` block is every
 * following line that is blank or indented, up to the next column-zero line.
 * Folded and literal blocks are both joined with spaces -- the text is only
 * ever searched, never shown.
 *
 * @param text Raw file contents.
 * @returns The description, or "" when there is none.
 */
export function readDescription(text: string): string {
  const lines = text.split("\n");
  const at = lines.findIndex((l) => /^description:/.test(l));
  if (at === -1) return "";
  const inline = scalarValue(lines[at].slice("description:".length));
  if (inline !== null) return inline;
  const body: string[] = [];
  for (const line of lines.slice(at + 1)) {
    if (line.trim() !== "" && !/^\s/.test(line)) break;
    if (line.trim() !== "") body.push(line.trim());
  }
  return body.join(" ");
}

/**
 * Words too common in alert text, or in every definition, to say anything
 * about which target an alert is about.
 */
const RESOLVE_STOPWORDS = new Set([
  "a",
  "an",
  "and",
  "are",
  "at",
  "be",
  "by",
  "for",
  "from",
  "has",
  "in",
  "is",
  "it",
  "of",
  "on",
  "or",
  "the",
  "to",
  "was",
  "with",
  "alert",
  "error",
  "failed",
  "failing",
  "failure",
  "model",
  "ok",
  "run",
  "stale",
  "swamp",
  "warning",
  "workflow",
]);

/**
 * Split text into lowercase words on anything not a letter or digit.
 *
 * @param text Free text, a name, a type or a tag.
 * @returns Words in order, duplicates kept.
 */
function words(text: string): string[] {
  return text.toLowerCase().split(/[^a-z0-9]+/).filter((w) => w !== "");
}

/**
 * The distinct words of free alert text that can identify a target.
 *
 * @param text Alert text as an operator or agent passed it.
 * @returns Lowercase words, in first-seen order, stopwords dropped.
 */
export function resolveTokens(text: string): string[] {
  return [...new Set(words(text))].filter((w) => !RESOLVE_STOPWORDS.has(w));
}

/** One definition free alert text may be about. */
export interface Resolution {
  name: string;
  /** "model" or "workflow". */
  kind: string;
  /** The model type, or literal "workflow". */
  type: string;
  /** The definition's `runs-on` tag: where it is scheduled; null if none. */
  runsOn: string | null;
  /** Higher is a better match; comparable only within one call. */
  score: number;
  /** The alert words this definition matched. */
  matched: string[];
  /** Repo-relative definition file. */
  definitionPath: string;
}

/**
 * Where a matched word was found, and what it is worth.
 *
 * A word in the name is the strongest evidence -- alerts quote names, and
 * names are short. The type and tags are written about the definition too,
 * but are shared by many. A description is long prose, so any one word in it
 * says least.
 */
const RESOLVE_WEIGHT = { name: 3, meta: 2, description: 1 };

/**
 * Bonus when the alert quotes a definition's whole name, word for word.
 *
 * `backlog-groom-judgement` names a step of `backlog-groom`; every word of
 * the name appears, in order, so the name is almost certainly what was meant.
 */
const RESOLVE_WHOLE_NAME = 3;

/** Whether `needle` occurs as a contiguous run inside `hay`. */
function containsRun(hay: string[], needle: string[]): boolean {
  if (needle.length === 0 || needle.length > hay.length) return false;
  for (let i = 0; i + needle.length <= hay.length; i++) {
    if (needle.every((w, j) => hay[i + j] === w)) return true;
  }
  return false;
}

/**
 * Rank definitions by how well free alert text matches them.
 *
 * An alert names its target in its own words -- `cold-storage disk-reports
 * stale`, a step name, a type -- and seldom by the exact definition name
 * `investigate` needs. Each alert word scores once, by the strongest place it
 * is found: the name, then the type and tags, then the description. A
 * definition whose whole name appears in the text gets a bonus. Token overlap
 * only, no fuzzy matching, so every score can be explained from `matched`.
 *
 * Ties go to workflows: a scheduled workflow is what raises an alert, and
 * investigating the workflow reaches its failing step's model anyway.
 *
 * @param text Alert text.
 * @param definitions Every definition, as `listDefinitions` returns them.
 * @param limit Most matches to return.
 * @returns Best matches first; never a definition matching no word.
 */
export function resolveText(
  text: string,
  definitions: ResolvedTarget[],
  limit = 5,
): Resolution[] {
  const query = resolveTokens(text);
  const raw = words(text);
  const out: Resolution[] = [];
  for (const d of definitions) {
    const name = new Set(words(d.name));
    const meta = new Set([
      ...(d.kind === "model" ? words(d.type) : []),
      ...Object.entries(d.tags).flatMap(([k, v]) => [
        ...words(k),
        ...words(v),
      ]),
    ]);
    const description = new Set(words(d.description ?? ""));
    let score = 0;
    const matched: string[] = [];
    for (const w of query) {
      const weight = name.has(w)
        ? RESOLVE_WEIGHT.name
        : meta.has(w)
        ? RESOLVE_WEIGHT.meta
        : description.has(w)
        ? RESOLVE_WEIGHT.description
        : 0;
      if (weight === 0) continue;
      score += weight;
      matched.push(w);
    }
    if (score === 0) continue;
    if (containsRun(raw, words(d.name))) score += RESOLVE_WHOLE_NAME;
    out.push({
      name: d.name,
      kind: d.kind,
      type: d.type,
      runsOn: d.tags["runs-on"] ?? null,
      score,
      matched,
      definitionPath: d.definitionPath,
    });
  }
  const kindOrder = (k: string) => (k === "workflow" ? 0 : 1);
  out.sort((a, b) =>
    b.score - a.score || kindOrder(a.kind) - kindOrder(b.kind) ||
    a.name.localeCompare(b.name)
  );
  return out.slice(0, limit);
}

/** Render a `resolve` result as short lines for a chat reply. */
export function buildResolveSummary(
  text: string,
  matches: Resolution[],
): string {
  if (matches.length === 0) {
    return `Nothing matched "${text}". Run \`recent\` to list what failed ` +
      `instead.`;
  }
  return [
    `Best matches for "${text}":`,
    ...matches.map((m, i) =>
      `${i + 1}. ${m.name} (${m.kind}` +
      (m.runsOn ? `, runs-on ${m.runsOn}` : "") +
      `) score ${m.score}: ${m.matched.join(", ")}`
    ),
    `Run \`investigate\` with target=${matches[0].name} ` +
    `kind=${matches[0].kind}.`,
  ].join("\n");
}

/**
 * Recursively yield every .yaml file under a directory.
 *
 * A missing directory yields nothing rather than throwing: a repo need not have
 * both models/ and workflows/, and an extension-only repo has neither.
 *
 * Entries are collected before iterating because `Deno.readDir` is lazy -- it
 * returns an iterator that throws on first read, not at the call, so wrapping
 * only the call would let ENOENT escape from the `for await` instead.
 */
async function* yamlFiles(dir: string): AsyncGenerator<string> {
  let entries: Deno.DirEntry[];
  try {
    entries = await Array.fromAsync(Deno.readDir(dir));
  } catch {
    return;
  }
  for (const entry of entries) {
    const path = `${dir}/${entry.name}`;
    if (entry.isDirectory) {
      yield* yamlFiles(path);
    } else if (entry.isFile && entry.name.endsWith(".yaml")) {
      // .yaml.example files are templates, not live definitions.
      yield path;
    }
  }
}

/**
 * Find every model or workflow definition carrying a name.
 *
 * Returns all matches rather than the first, because a model and a workflow are
 * allowed to share a name. Silently preferring one would investigate a
 * different thing than the operator named and give no sign of it -- so the
 * caller is handed the ambiguity to report.
 *
 * @param repoDir Repository root.
 * @param target Definition name to find.
 * @param kind "model", "workflow", or "auto" to search both.
 * @returns Matches in search order (models before workflows); empty if none.
 */
export async function resolveTargets(
  repoDir: string,
  target: string,
  kind: string,
): Promise<ResolvedTarget[]> {
  return (await listDefinitions(repoDir, kind)).filter((d) =>
    d.name === target
  );
}

/**
 * Every model or workflow definition in the repo, in search order.
 *
 * The one walk behind name resolution, name suggestions, the definition path
 * `recent` reports, and the scheduled workflows it checks for a missing run.
 *
 * @param repoDir Repository root.
 * @param kind "model", "workflow", or "auto" for both.
 */
export async function listDefinitions(
  repoDir: string,
  kind: string,
): Promise<ResolvedTarget[]> {
  const search: { kind: string; dir: string }[] = [];
  if (kind === "model" || kind === "auto") {
    search.push({ kind: "model", dir: `${repoDir}/models` });
  }
  if (kind === "workflow" || kind === "auto") {
    search.push({ kind: "workflow", dir: `${repoDir}/workflows` });
  }

  const matches: ResolvedTarget[] = [];
  for (const { kind: k, dir } of search) {
    for await (const path of yamlFiles(dir)) {
      let text: string;
      try {
        text = await Deno.readTextFile(path);
      } catch (err) {
        // An unreadable neighbour must not abort the search -- but a
        // permission denial is a broken environment, not a stray file, and
        // silently skipping it would report "target not found" for a repo
        // that is full of targets.
        if (err instanceof Deno.errors.PermissionDenied) throw err;
        continue;
      }
      const doc = readTopLevelScalars(text);
      const id = doc.id;
      if (!doc.name || !id) continue;
      const type = k === "workflow" ? "workflow" : doc.type;
      if (!type) continue;
      matches.push({
        name: doc.name,
        kind: k,
        type,
        id,
        definitionPath: path.startsWith(repoDir + "/")
          ? path.slice(repoDir.length + 1)
          : path,
        schedule: k === "workflow"
          ? readNestedScalars(text, "trigger").schedule ?? null
          : null,
        tags: readNestedScalars(text, "tags"),
        description: readDescription(text),
      });
    }
  }
  return matches;
}

/* ------------------------------------------------------------------ *
 * Recent failures
 *
 * `investigate` needs a name, and an alert does not always carry one: a
 * relayed notification can lose its body, and an operator asking "what
 * just broke?" has no name to give. The summary reports that answer the
 * question are already stored as data, so one query across every model
 * finds them -- including workflows bundled inside extensions, which have
 * no definition file in the repo for a name lookup to find.
 * ------------------------------------------------------------------ */

export const WORKFLOW_SUMMARY = "report-swamp-workflow-summary-json";
export const METHOD_SUMMARY = "report-swamp-method-summary-json";

/** The latest summary report of one target, as read back for `recent`. */
export interface SummaryHead {
  /** Definition name, from the report's `modelName` tag. */
  target: string;
  /** "model" or "workflow". */
  kind: string;
  /** The model type (e.g. `@acme/thing`), or literal "workflow". */
  type: string;
  /** When the report was written, ISO-8601 UTC. */
  createdAt: string;
  /** The parsed report body. */
  body: Record<string, unknown>;
  /** Where the report lives, so older versions can be walked. */
  modelId?: string;
  dataName?: string;
  version?: number;
}

/**
 * A target that failed inside the window and has succeeded since.
 *
 * Its latest summary is a success, so a head-only read cannot see it -- yet
 * "what failed overnight?" is exactly the question a daily summary asks, and
 * the answer has to name the instance even when it has already recovered.
 */
export interface RecoveredFailure {
  /** The newest failed run inside the window, shaped as a head. */
  failed: SummaryHead;
  /** When the first success after that failure was recorded. */
  recoveredAt: string;
  /** The method that success ran, to tell a retry from a different call. */
  recoveredMethod: string | null;
  /** Failed runs inside the window. */
  failureCount: number;
}

/**
 * A failure followed this soon by a success of the same method is a caller
 * correcting its own input -- an agent or a person retrying with a different
 * value -- not the remote coming back. Nothing that heals on its own does so
 * in under a minute and on the very next call.
 */
export const QUICK_RETRY_SECONDS = 60;

/** The widest `recent` window; a wider request is capped, not refused. */
export const MAX_WINDOW_HOURS = 720;

/** A `key=value` placement tag, e.g. `runs-on=scheduler-a`. */
export interface Placement {
  key: string;
  value: string;
}

/**
 * Parse a `key=value` placement tag, or null for an empty one.
 *
 * @throws When the text is not `key=value` -- a placement that silently
 *   matched nothing would make every scheduled workflow read as elsewhere.
 */
export function parsePlacement(text: string | undefined): Placement | null {
  const t = (text ?? "").trim();
  if (t === "") return null;
  const m = /^([^=\s]+)=(.+)$/.exec(t);
  if (!m) {
    throw new Error(
      `placementTag must be key=value (e.g. runs-on=primary), got "${t}".`,
    );
  }
  return { key: m[1], value: m[2].trim() };
}

/** True when no placement was given, or the tags carry it. */
export function placedHere(
  tags: Record<string, string>,
  placement: Placement | null,
): boolean {
  return placement === null || tags[placement.key] === placement.value;
}

/** One target that failed within the window. */
export interface RecentFailure {
  target: string;
  kind: string;
  /**
   * The model type, or "workflow". A run-history line or an alert often names
   * only the type, and one type has many instances; this is what maps one to
   * the other without a catalog search.
   */
  targetType: string;
  failedAt: string;
  status: string;
  failingMethod: string | null;
  rootCauseModel: string | null;
  category: string;
  meaning: string;
  nextStep: string;
  error: string | null;
  redactions: number;
  redactedKinds: string[];
  /** True when the target's latest run failed; false when it has recovered. */
  failing: boolean;
  /** When a recovered target next succeeded; null while still failing. */
  recoveredAt: string | null;
  /**
   * Failed runs inside the window for a recovered target. Null for one still
   * failing: its latest run is all that is read, and `investigate` counts the
   * streak.
   */
  failureCount: number | null;
  /**
   * The failure is one of this investigator's own runs, failed by its
   * caller's input -- a bad name or argument. A caller error, not a fleet
   * failure. Any other failure of the investigator is not flagged.
   */
  selfInflicted: boolean;
  /**
   * The newest failure was followed within `QUICK_RETRY_SECONDS` by a success
   * of the same method: a caller correcting its own input. Always false for
   * a target still failing.
   */
  quickRetry: boolean;
  /** Repo-relative definition file; null for one bundled in an extension. */
  definitionPath: string | null;
}

/** A scheduled workflow with no recorded run at all in this datastore. */
export interface NeverRun {
  target: string;
  schedule: string;
  definitionPath: string;
}

/** What `recent` found, before it is recorded. */
export interface RecentSelection {
  /** Still-failing targets first, then recovered ones; newest first in each. */
  failures: RecentFailure[];
  /** Targets that failed inside the window beyond `limit`. */
  omitted: number;
  /**
   * Targets still failing whose last run is older than the window -- a
   * weekly job broken for days. Counted so a narrow window cannot make them
   * read as healthy; widen the window to list them.
   */
  staleFailing: number;
  /**
   * Scheduled workflows that have never run here. A schedule that never fires
   * leaves no failure behind, so it is invisible to every other check.
   */
  scheduledNeverRun: NeverRun[];
}

/** The first failed step a workflow summary records, and its own error. */
export interface WorkflowStepFailure {
  stepModel: string | null;
  stepMethod: string | null;
  /** The step's error as the workflow run recorded it; null when absent. */
  errorMessage: string | null;
}

/**
 * Read the first entry of a workflow summary's `failures`, or null when it
 * has none.
 *
 * The workflow run records each failed step's own error as `errorMessage`.
 * That is the error of *this* run. The step model's latest method summary is
 * not: by the time anyone investigates, the model may have run again and
 * succeeded -- and an expression that failed to evaluate never ran the model
 * at all, so its summary never held the error in the first place.
 */
export function firstWorkflowFailure(
  body: Record<string, unknown> | null | undefined,
): WorkflowStepFailure | null {
  if (!Array.isArray(body?.failures) || body.failures.length === 0) {
    return null;
  }
  const first = body.failures[0] as Record<string, unknown> | undefined;
  const str = (v: unknown) =>
    typeof v === "string" && v.trim() !== "" ? v : null;
  return {
    stepModel: str(first?.modelName),
    stepMethod: str(first?.methodName),
    errorMessage: str(first?.errorMessage),
  };
}

/**
 * Describe one failing summary: where it broke, and why.
 *
 * A workflow summary names the failing step and, usually, the error that
 * step recorded in this run. Only when it carries no error is the step's
 * model looked up among the method summaries the same query already
 * returned -- the same hop `investigate` makes, without a second read.
 *
 * @param head The failing target's latest summary.
 * @param methodBodies Latest method-summary body per model name.
 */
export function describeFailure(
  head: SummaryHead,
  methodBodies: Map<string, Record<string, unknown>>,
): RecentFailure {
  const body = head.body;
  let error = typeof body.error === "string" ? body.error : null;
  let failingMethod = typeof body.methodName === "string"
    ? body.methodName
    : null;
  let rootCauseModel: string | null = null;

  const step = error === null ? firstWorkflowFailure(body) : null;
  if (step) {
    const { stepModel, stepMethod } = step;
    if (step.errorMessage !== null) {
      error = step.errorMessage;
    } else if (stepModel) {
      const sub = methodBodies.get(stepModel);
      if (typeof sub?.error === "string") {
        error = sub.error;
        rootCauseModel = stepModel;
      }
    }
    if (stepModel) {
      failingMethod = stepMethod ? `${stepModel} → ${stepMethod}` : stepModel;
    }
  }

  // Classify before redacting, for the reason given in `investigate`.
  // Only failing heads reach here, but the status decides, not the caller.
  const c = classifyError(error, body.status !== "succeeded");
  const r = redactSecrets(error);
  return {
    target: head.target,
    kind: head.kind,
    targetType: head.type,
    failedAt: head.createdAt,
    status: typeof body.status === "string" ? body.status : "unknown",
    failingMethod,
    rootCauseModel,
    category: c.category,
    meaning: c.meaning,
    nextStep: c.nextStep,
    error: error === null ? null : r.text,
    redactions: r.count,
    redactedKinds: r.kinds,
    failing: true,
    recoveredAt: null,
    failureCount: null,
    selfInflicted: false,
    quickRetry: false,
    definitionPath: null,
  };
}

/** Whether a recovered failure was a caller retrying with different input. */
export function isQuickRetry(r: RecoveredFailure): boolean {
  const failedAt = Date.parse(r.failed.createdAt);
  const backAt = Date.parse(r.recoveredAt);
  if (isNaN(failedAt) || isNaN(backAt)) return false;
  const method = r.failed.body.methodName;
  const sameMethod = typeof method !== "string" || r.recoveredMethod === null ||
    r.recoveredMethod === method;
  return sameMethod && backAt - failedAt <= QUICK_RETRY_SECONDS * 1000;
}

/**
 * Errors the investigator raises about its caller's input: a rejected
 * argument, a name that matches nothing, and the pre-2026.10.21 refusal for a
 * target with no runs. Only these make a failure of the investigator itself a
 * caller error. Anything else -- a lock timeout, a crash after an upgrade --
 * means the investigator is broken, and must be listed like any other failure
 * rather than filed away where nobody looks.
 */
const CALLER_ERROR_PATTERNS = [
  /^No (model or workflow|model|workflow) named "/,
  /^No summary reports recorded for /,
];

/** Whether an investigator failure was caused by its caller's input. */
export function isCallerError(f: Pick<RecentFailure, "category" | "error">) {
  return f.category === "caller_args" ||
    CALLER_ERROR_PATTERNS.some((p) => p.test(f.error ?? ""));
}

/** What `selectRecentFailures` needs beyond the window itself. */
export interface RecentOptions {
  /** The investigator's own model type; its failures are caller errors. */
  selfType?: string;
  /** Every definition, to report paths and find scheduled never-run ones. */
  definitions?: ResolvedTarget[];
  /** Only workflows carrying this tag count as scheduled to run here. */
  placement?: Placement | null;
}

/**
 * Pick the targets that failed within the window.
 *
 * Anything not an explicit success counts as a failure, as in
 * `reconstructTimeline`. Targets still failing come first, then those that
 * failed and have since recovered; each group is newest first, so the thing
 * that broke most recently -- usually the one an alert is about -- leads.
 *
 * @param heads Latest summary per target, any order.
 * @param nowMs Reference time in epoch milliseconds.
 * @param withinHours Window size.
 * @param kind "model", "workflow", or "auto" for both.
 * @param limit Maximum failures to return.
 * @param recovered Targets found by `readRecoveredFailures`.
 * @param opts The investigator's own type, the repo's definitions, and the
 *   placement tag -- each optional, each only adding to what is reported.
 */
export function selectRecentFailures(
  heads: SummaryHead[],
  nowMs: number,
  withinHours: number,
  kind: string,
  limit: number,
  recovered: RecoveredFailure[] = [],
  opts: RecentOptions = {},
): RecentSelection {
  const since = nowMs - withinHours * 3_600_000;
  const methodBodies = new Map<string, Record<string, unknown>>();
  for (const h of heads) {
    if (h.kind === "model") methodBodies.set(h.target, h.body);
  }

  const inWindow: SummaryHead[] = [];
  let staleFailing = 0;
  for (const h of heads) {
    if (kind !== "auto" && h.kind !== kind) continue;
    if (h.body.status === "succeeded") continue;
    const t = Date.parse(h.createdAt);
    // An unreadable timestamp cannot be placed outside the window, so it is
    // listed rather than dropped: missing a failure is the worse mistake.
    if (!isNaN(t) && t < since) {
      staleFailing++;
      continue;
    }
    inWindow.push(h);
  }
  // Undated entries sort last rather than lexically ahead of every date.
  const when = (h: SummaryHead) => {
    const t = Date.parse(h.createdAt);
    return isNaN(t) ? -Infinity : t;
  };
  inWindow.sort((a, b) => when(b) - when(a));

  const back = recovered
    .filter((r) => kind === "auto" || r.failed.kind === kind)
    .sort((a, b) => when(b.failed) - when(a.failed));

  const defs = opts.definitions ?? [];
  const pathOf = (target: string, k: string) =>
    defs.find((d) => d.name === target && d.kind === k)?.definitionPath ??
      null;
  const mark = (f: RecentFailure): RecentFailure => ({
    ...f,
    selfInflicted: opts.selfType !== undefined &&
      f.targetType === opts.selfType && isCallerError(f),
    definitionPath: pathOf(f.target, f.kind),
  });

  const listed: RecentFailure[] = [
    ...inWindow.map((h) => mark(describeFailure(h, methodBodies))),
    ...back.map((r) =>
      mark({
        ...describeFailure(r.failed, methodBodies),
        failing: false,
        recoveredAt: r.recoveredAt,
        failureCount: r.failureCount,
        quickRetry: isQuickRetry(r),
      })
    ),
  ];
  // The investigator's own failures go last: they are about whoever called
  // it, so they must never crowd a fleet failure out of `limit`.
  const all = [
    ...listed.filter((f) => !f.selfInflicted),
    ...listed.filter((f) => f.selfInflicted),
  ];

  // A workflow is "run" here if any summary of it exists, in or out of the
  // window: this looks for schedules that have never fired at all.
  const ran = new Set(
    heads.filter((h) => h.kind === "workflow").map((h) => h.target),
  );
  const scheduledNeverRun: NeverRun[] = kind === "model" ? [] : defs
    .filter((d) =>
      d.kind === "workflow" && d.schedule !== null && !ran.has(d.name) &&
      placedHere(d.tags, opts.placement ?? null)
    )
    .map((d) => ({
      target: d.name,
      schedule: d.schedule!,
      definitionPath: d.definitionPath,
    }))
    .sort((a, b) => a.target.localeCompare(b.target));

  return {
    failures: all.slice(0, limit),
    omitted: Math.max(0, all.length - limit),
    staleFailing,
    scheduledNeverRun,
  };
}

/**
 * Find targets whose latest run succeeded but which failed inside the window.
 *
 * For each such target, walk its summary versions newest-first -- the same
 * walk `investigate` makes, where every version is one recorded run -- and
 * stop at the first version older than the window.
 *
 * @param heads Latest summary per target, as `readSummaryHeads` returns them.
 * @param maxVersions Most versions to read per target.
 * @returns The recovered targets, and how many walks hit `maxVersions`
 *   before leaving the window -- a failure beyond that is not seen.
 */
export async function readRecoveredFailures(
  context: Pick<Context, "dataRepository">,
  heads: SummaryHead[],
  nowMs: number,
  withinHours: number,
  kind: string,
  maxVersions: number,
): Promise<{ recovered: RecoveredFailure[]; truncated: number }> {
  const since = nowMs - withinHours * 3_600_000;
  const decoder = new TextDecoder();
  const recovered: RecoveredFailure[] = [];
  let truncated = 0;

  for (const h of heads) {
    if (kind !== "auto" && h.kind !== kind) continue;
    if (h.body.status !== "succeeded") continue;
    if (!h.modelId || !h.dataName || h.version === undefined) continue;
    // A head older than the window means every earlier run is older still.
    const headAt = Date.parse(h.createdAt);
    if (!isNaN(headAt) && headAt < since) continue;

    const methodOf = (b: Record<string, unknown>) =>
      typeof b.methodName === "string" ? b.methodName : null;
    let newerAt = h.createdAt;
    let newerMethod = methodOf(h.body);
    let failed: SummaryHead | null = null;
    let recoveredAt = "";
    let recoveredMethod: string | null = null;
    let failureCount = 0;
    let leftWindow = false;
    const floor = Math.max(1, h.version - maxVersions);
    for (let v = h.version - 1; v >= floor; v--) {
      const meta = await context.dataRepository.findByName(
        h.type,
        h.modelId,
        h.dataName,
        v,
      );
      const bytes = await context.dataRepository.getContent(
        h.type,
        h.modelId,
        h.dataName,
        v,
      );
      if (!meta || !bytes) continue; // Garbage-collected mid-range.
      const at = isoTime(meta.createdAt);
      const t = Date.parse(at);
      if (!isNaN(t) && t < since) {
        leftWindow = true;
        break;
      }
      let body: Record<string, unknown>;
      try {
        body = JSON.parse(decoder.decode(bytes));
      } catch {
        continue; // A corrupt version must not abort the walk.
      }
      if (body.status === "succeeded") {
        // Only successes newer than the newest failure mark the recovery.
        if (!failed) {
          newerAt = at;
          newerMethod = methodOf(body);
        }
        continue;
      }
      failureCount++;
      if (!failed) {
        failed = { ...h, createdAt: at, body, version: v };
        recoveredAt = newerAt;
        recoveredMethod = newerMethod;
      }
    }
    // Reaching version 1 is the whole history, not a truncated walk.
    if (!leftWindow && floor > 1) truncated++;
    if (failed) {
      recovered.push({ failed, recoveredAt, recoveredMethod, failureCount });
    }
  }
  return { recovered, truncated };
}

/** Render a `recent` result as a paragraph for a notification or chat. */
export function buildRecentSummary(
  sel: RecentSelection,
  withinHours: number,
  requestedHours = withinHours,
): string {
  const lines: string[] = [];
  if (requestedHours > withinHours) {
    lines.push(
      `Asked for ${requestedHours}h; the window is capped at ${withinHours}h.`,
    );
  }
  const fleet = sel.failures.filter((f) => !f.selfInflicted);
  const own = sel.failures.filter((f) => f.selfInflicted);
  if (sel.failures.length === 0) {
    lines.push(`Nothing has failed in the last ${withinHours}h.`);
  } else {
    const back = fleet.filter((f) => !f.failing).length;
    lines.push(
      fleet.length === 0
        ? `Nothing in the fleet failed in the last ${withinHours}h.`
        : `${fleet.length + sel.omitted} target(s) failed in the last ` +
          `${withinHours}h, newest first` +
          (back > 0 ? `; still failing listed before recovered:` : ":"),
    );
    for (const f of fleet) {
      const where = f.failingMethod ? ` at \`${f.failingMethod}\`` : "";
      // A model's type is what a run-history line names; show it so the two
      // can be matched by eye.
      const what = f.kind === "model" ? `model ${f.targetType}` : f.kind;
      const state = f.failing
        ? `, ${f.failedAt}`
        : ` — failed ${f.failureCount}x, last at ${f.failedAt}, recovered ` +
          `at ${f.recoveredAt}`;
      const retry = f.quickRetry
        ? " — the same method succeeded seconds later: a caller correcting " +
          "its own input, not the remote recovering"
        : "";
      lines.push(
        `- ${f.target} (${what})${where} — **${f.category}**${state}${retry}`,
      );
    }
    if (sel.omitted > 0) {
      lines.push(`- …and ${sel.omitted} more; raise \`limit\` to list them.`);
    }
    if (own.length > 0) {
      // Counted apart, never as fleet failures: these are this investigator's
      // own runs, failed by a bad name or argument from whoever called it.
      const what = [...new Set(own.map((f) => f.failingMethod ?? f.target))];
      lines.push(
        `${own.length} failure(s) were this investigator's own runs ` +
          `(${what.join(", ")}): a caller's bad name or argument, not a ` +
          `fleet failure. Nothing to fix in the fleet for these.`,
      );
    }
    if (fleet.length > 0) {
      lines.push(
        "Run `investigate` on one of these for its full timeline and next " +
          "step.",
      );
    }
  }
  if (sel.scheduledNeverRun.length > 0) {
    lines.push(
      `${sel.scheduledNeverRun.length} scheduled workflow(s) have no recorded ` +
        `run in this datastore: ` +
        sel.scheduledNeverRun.map((n) => `${n.target} (\`${n.schedule}\`)`)
          .join(", ") +
        `. A schedule that never fires leaves no failure behind; check the ` +
        `scheduler that is meant to run each one.`,
    );
  }
  if (sel.staleFailing > 0) {
    lines.push(
      `${sel.staleFailing} other target(s) are still failing but last ran ` +
        `before this window; widen \`withinHours\` to see them.`,
    );
  }
  return lines.join("\n");
}

/* ------------------------------------------------------------------ *
 * Model definition
 * ------------------------------------------------------------------ */

const InvestigationSchema = z.object({
  target: z.string(),
  targetKind: z.string(),
  targetType: z.string(),
  targetId: z.string(),
  definitionPath: z.string(),
  investigatedAt: z.string(),
  /** True when the target's most recent recorded run failed. */
  failing: z.boolean(),
  currentStatus: z.string(),
  category: z.string(),
  categoryMatched: z.boolean(),
  meaning: z.string(),
  nextStep: z.string(),
  error: z.string().nullable(),
  failingMethod: z.string().nullable(),
  /** Set when a workflow failure was chased into the model that caused it. */
  rootCauseModel: z.string().nullable(),
  /** How many secret values were redacted from the error before recording. */
  redactions: z.number(),
  /** Which kinds of secret were redacted, for judging what was removed. */
  redactedKinds: z.array(z.string()),
  consecutiveFailures: z.number(),
  firstFailureAt: z.string().nullable(),
  lastSuccessAt: z.string().nullable(),
  lastSuccessMethod: z.string().nullable(),
  successOutsideWindow: z.boolean(),
  runsExamined: z.number(),
  /** A workflow's trigger cron; null for a model or an unscheduled workflow. */
  schedule: z.string().nullable(),
  /**
   * Argument names the failing run took per call -- set by whoever called
   * it, never in the definition. Values are not recorded, only names.
   */
  callArgs: z.array(z.string()),
  /** Argument names set in the definition itself (global arguments). */
  definitionArgs: z.array(z.string()),
  /** One-paragraph plain-language finding, suitable for a notification body. */
  summary: z.string(),
});

const RecentSchema = z.object({
  checkedAt: z.string(),
  withinHours: z.number(),
  /** Start of the window, ISO-8601 UTC. */
  since: z.string(),
  kind: z.string(),
  /** How many targets' latest summary reports were read. */
  summariesExamined: z.number(),
  failures: z.array(z.object({
    target: z.string(),
    kind: z.string(),
    targetType: z.string(),
    failedAt: z.string(),
    status: z.string(),
    failingMethod: z.string().nullable(),
    rootCauseModel: z.string().nullable(),
    category: z.string(),
    meaning: z.string(),
    nextStep: z.string(),
    error: z.string().nullable(),
    redactions: z.number(),
    redactedKinds: z.array(z.string()),
    /** False when the target failed in the window and has since recovered. */
    failing: z.boolean(),
    recoveredAt: z.string().nullable(),
    /** Failed runs in the window, for a recovered target; else null. */
    failureCount: z.number().nullable(),
    /** One of this investigator's own runs: a caller error. */
    selfInflicted: z.boolean(),
    /** Recovered by the same method within a minute: a caller's retry. */
    quickRetry: z.boolean(),
    /** Repo-relative definition file; null when bundled in an extension. */
    definitionPath: z.string().nullable(),
  })),
  /** Targets that failed inside the window left out by `limit`. */
  omitted: z.number(),
  /** Targets still failing whose last run predates the window. */
  staleFailing: z.number(),
  /** The window asked for, before capping at the maximum. */
  requestedHours: z.number(),
  /** Scheduled workflows with no recorded run here at all. */
  scheduledNeverRun: z.array(z.object({
    target: z.string(),
    schedule: z.string(),
    definitionPath: z.string(),
  })),
  /** The placement tag the never-run check was limited to, if any. */
  placementTag: z.string().nullable(),
  /**
   * Recovered targets whose history walk hit `maxVersions` inside the window;
   * an older failure of theirs was not seen. Raise `maxVersions` to see it.
   */
  historyTruncated: z.number(),
  /** Plain-language list, suitable for a notification body. */
  summary: z.string(),
});

const ResolveSchema = z.object({
  resolvedAt: z.string(),
  /** The alert text as given, with any identifiable secret value redacted. */
  text: z.string(),
  /** The words that were matched against definitions. */
  tokens: z.array(z.string()),
  kind: z.string(),
  /** How many definitions were searched. */
  definitionsExamined: z.number(),
  matches: z.array(z.object({
    name: z.string(),
    kind: z.string(),
    type: z.string(),
    runsOn: z.string().nullable(),
    score: z.number(),
    matched: z.array(z.string()),
    definitionPath: z.string(),
  })),
  /** Short ranked list, suitable for a chat reply. */
  summary: z.string(),
});

const GlobalArgsSchema = z.object({
  repoDir: z.string().optional().describe(
    "Repository root to investigate. Defaults to the repo the model runs in.",
  ),
});

interface DataRecord {
  version: number;
  /** The repository hands this back as a Date; normalize before reporting. */
  createdAt?: string | Date;
}

/**
 * Render a recorded timestamp as ISO-8601 UTC.
 *
 * Timestamps go into notifications and get compared against other operators'
 * logs, so they must not render in whatever local timezone the investigating
 * host happens to sit in.
 */
function isoTime(value: string | Date | undefined): string {
  if (value === undefined) return "unknown";
  const d = value instanceof Date ? value : new Date(value);
  return isNaN(d.getTime()) ? "unknown" : d.toISOString();
}

/** The fields `recent` uses from a `queryData` result. */
interface QueryRecord {
  name: string;
  version: number;
  modelId: string;
  modelType: string;
  tags?: Record<string, string>;
}

interface Context {
  repoDir: string;
  globalArgs: z.infer<typeof GlobalArgsSchema>;
  writeResource: (
    spec: string,
    instance: string,
    data: unknown,
  ) => Promise<unknown>;
  dataRepository: {
    findByName: (
      type: string,
      modelId: string,
      dataName: string,
      version?: number,
    ) => Promise<DataRecord | null>;
    getContent: (
      type: string,
      modelId: string,
      dataName: string,
      version?: number,
    ) => Promise<Uint8Array | null>;
  };
  /** Absent on runtimes that predate cross-model queries. */
  queryData?: (predicate: string) => Promise<QueryRecord[]>;
  logger: {
    info: (msg: string, props?: unknown) => void;
    warning: (msg: string, props?: unknown) => void;
  };
}

/**
 * Read the latest summary report of every model and workflow in the repo.
 *
 * One query finds every summary; each body is then read by its exact
 * version. The query result's own attributes cannot be used for this: a
 * summary is stored as a raw JSON report, not a resource, so `status` is not
 * queryable and has to come from the content.
 *
 * A record that cannot be read or parsed is skipped rather than aborting the
 * sweep -- one corrupt report must not hide every other failure.
 *
 * @returns The heads plus how many records were skipped.
 */
export async function readSummaryHeads(
  context: Pick<Context, "queryData" | "dataRepository">,
): Promise<{ heads: SummaryHead[]; skipped: number }> {
  if (!context.queryData) {
    throw new Error(
      "This swamp runtime does not provide context.queryData, which `recent` " +
        "needs to find summaries across models. Upgrade swamp, or use " +
        "`investigate` with a target name.",
    );
  }
  const records = await context.queryData(
    `name == "${WORKFLOW_SUMMARY}" || name == "${METHOD_SUMMARY}"`,
  );
  const decoder = new TextDecoder();
  const heads: SummaryHead[] = [];
  let skipped = 0;
  for (const rec of records) {
    const meta = await context.dataRepository.findByName(
      rec.modelType,
      rec.modelId,
      rec.name,
      rec.version,
    );
    const bytes = await context.dataRepository.getContent(
      rec.modelType,
      rec.modelId,
      rec.name,
      rec.version,
    );
    if (!meta || !bytes) {
      skipped++;
      continue;
    }
    let body: Record<string, unknown>;
    try {
      body = JSON.parse(decoder.decode(bytes));
    } catch {
      skipped++;
      continue;
    }
    heads.push({
      // The tag carries the definition name; the id is the fallback so an
      // untagged report is still listed, just less readably.
      target: rec.tags?.modelName ?? rec.modelId,
      kind: rec.name === WORKFLOW_SUMMARY ? "workflow" : "model",
      type: rec.modelType,
      createdAt: isoTime(meta.createdAt),
      body,
      modelId: rec.modelId,
      dataName: rec.name,
      version: rec.version,
    });
  }
  return { heads, skipped };
}

/**
 * The instance name a finding for `target` is stored under.
 *
 * Swamp rejects data names containing `/`, `\`, `..` or null bytes as path
 * traversal. A collective-scoped name like `@acme/nightly-backup` therefore
 * cannot be used verbatim -- and since bundling a workflow inside an extension
 * *requires* that scoping, the targets most likely to need investigating were
 * exactly the ones whose findings could not be written.
 *
 * Percent-encoded rather than folded to a plain separator. Folding `/` to `-`
 * would map `@acme/thing` and `@acme-thing` onto one instance and silently
 * interleave two targets' histories; encoding keeps the mapping injective.
 * `%` is escaped first so the encoding cannot be forged by a name that already
 * contains one. The finding's `target` field always carries the real,
 * unmodified name.
 *
 * @param name Target name as the operator gave it.
 * @returns A name safe to use as a data instance.
 */
export function sanitizeInstanceName(name: string): string {
  const trimmed = name.trim();
  if (trimmed === "") return "unnamed";
  const encoded = trimmed
    .replace(/%/g, "%25")
    .replace(/\.\./g, "%2E%2E")
    .replace(/\//g, "%2F")
    .replace(/\\/g, "%5C")
    // deno-lint-ignore no-control-regex
    .replace(/\x00/g, "%00")
    .replace(/\s/g, "%20");
  // `current`, `recent` and `resolve` are the stable handles. A target with one of those
  // names would overwrite the handle with a per-target finding, so its first
  // character is encoded too. Still injective: a literal `%` became `%25`.
  if (RESERVED_INSTANCES.has(encoded)) {
    return `%${encoded.charCodeAt(0).toString(16).toUpperCase()}` +
      encoded.slice(1);
  }
  return encoded;
}

/** Instance names the model writes to on every run, whatever the target. */
const RESERVED_INSTANCES = new Set(["current", "recent", "resolve"]);

/**
 * Write a finding under its per-target instance and under `current`.
 *
 * Two instances of the same finding, deliberately. The per-target instance
 * keeps history: investigate the same thing twice and the versions are
 * comparable to each other. Its name is sanitized, because swamp rejects `/`
 * in a data name and a bundled workflow's name is required to be
 * collective-scoped.
 *
 * `current` is the stable handle a workflow can reference without knowing the
 * target's name at all -- `data.latest('triage', 'current')`. Deriving the
 * instance from the target meant the reference had to reproduce the
 * sanitization in CEL, which is both awkward and one more place for the two to
 * drift apart.
 *
 * Concurrent investigations race on `current`; the per-target instance is the
 * one to read when that matters.
 */
async function recordFinding(
  context: Pick<Context, "writeResource">,
  finding: z.infer<typeof InvestigationSchema>,
): Promise<unknown[]> {
  const perTarget = await context.writeResource(
    "investigation",
    sanitizeInstanceName(finding.target),
    finding,
  );
  const current = await context.writeResource(
    "investigation",
    "current",
    finding,
  );
  return [perTarget, current];
}

/** Render the investigation as a paragraph an operator can act on directly. */
function buildSummary(
  t: ResolvedTarget,
  tl: Timeline,
  c: Classification,
  error: string | null,
  failingMethod: string | null,
  rootCauseModel: string | null,
  args: { call: string[]; definition: string[] } = { call: [], definition: [] },
): string {
  if (tl.currentStatus === "succeeded") {
    return `${t.name} (${t.kind}) is not currently failing -- its most ` +
      `recent recorded run succeeded. Nothing to investigate.`;
  }
  const where = failingMethod ? ` at \`${failingMethod}\`` : "";
  const parts = [
    `${t.name} (${t.kind}) is failing${where}, classified as ` +
    `**${c.category}**. ${c.meaning}`,
  ];
  if (tl.lastSuccess && tl.firstFailure) {
    parts.push(
      `It last worked at ${tl.lastSuccess.createdAt} and first failed at ` +
        `${tl.firstFailure.createdAt}; whatever changed between those two ` +
        `moments is the cause. ${tl.consecutiveFailures} consecutive ` +
        `failure(s) since.`,
    );
  } else if (tl.successOutsideWindow) {
    parts.push(
      `No success appears anywhere in the ${tl.examined} run(s) examined, so ` +
        `the boundary is outside the search window -- either older than the ` +
        `\`maxVersions\` limit or aged out of retention. Treat the start date ` +
        `as unknown rather than recent; raise maxVersions to look further ` +
        `back.`,
    );
  }
  if (rootCauseModel) {
    parts.push(
      `The workflow report named the failing step but not its cause; the ` +
        `error below was read from the \`${rootCauseModel}\` model that step ` +
        `invoked.`,
    );
  }
  if (error) parts.push(`Recorded error: ${error}`);
  // Where an input-shaped error points depends on where the input lives. A
  // per-call argument is not in the definition file, so "fix the YAML" is the
  // wrong advice for one -- and only the names are recorded, never values.
  if (
    (c.category === "config" || c.category === "caller_args") &&
    (args.call.length > 0 || args.definition.length > 0)
  ) {
    const list = (a: string[]) => a.length ? a.join(", ") : "none";
    parts.push(
      `Arguments passed by the caller on each run: ${list(args.call)}. Set ` +
        `in the definition (${t.definitionPath}): ${list(args.definition)}. ` +
        `Only names are recorded, not the values a run used.`,
    );
  }
  parts.push(`Next step: ${c.nextStep}`);
  return parts.join("\n\n");
}

/**
 * The finding for a target with no recorded run at all.
 *
 * This used to be an error, which had two costs: the investigation itself was
 * recorded as a failed run -- noise in the next `recent` -- and a scheduled
 * workflow that had never fired read as "nothing to investigate". That case is
 * the alarming one: a schedule that never runs leaves no failure anywhere.
 *
 * @param t The resolved target.
 * @param placement The placement tag this datastore runs, if given.
 */
export function neverRunFinding(
  t: ResolvedTarget,
  placement: Placement | null,
): { failing: boolean; classification: Classification; summary: string } {
  const scheduled = t.schedule !== null;
  const here = placedHere(t.tags, placement);
  const failing = scheduled && here;
  const placed = placement ? ` (${placement.key}=${placement.value})` : "";
  const elsewhere = placement && t.tags[placement.key]
    ? `${placement.key}=${t.tags[placement.key]}`
    : "another datastore";
  const meaning = !scheduled
    ? "No run of this target is recorded in this datastore, and it has no " +
      "schedule. It may only ever run by hand, or in another datastore."
    : here
    ? `It is scheduled (\`${t.schedule}\`) to run here${placed}, but no run ` +
      `is recorded at all. The scheduler is not firing it, or its history ` +
      `was lost.`
    : `It is scheduled (\`${t.schedule}\`) but placed on ${elsewhere}, not ` +
      `here${placed}, so no run here is expected.`;
  const nextStep = failing
    ? "Check the scheduler that should run it -- is the trigger registered, " +
      "and is its next run in the future? -- then whether this datastore is " +
      "younger than one schedule period. Run it once by hand if a slot was " +
      "missed."
    : "Investigate it where it runs; nothing here says it is broken.";
  return {
    failing,
    classification: {
      category: "never_run",
      matched: true,
      meaning,
      nextStep,
    },
    summary: `${t.name} (${t.kind}) has never run in this datastore` +
      (failing ? ", and is **failing** to run on schedule. " : ". ") +
      `${meaning}\n\nNext step: ${nextStep}`,
  };
}

/** This model's own type; its failures in `recent` are caller errors. */
export const MODEL_TYPE = "@sntxrr/swamp-triage/investigation";

// The type stays a string literal here: the registry catalog only lists a
// behavior whose `type` it can read without evaluating code.
export const model = {
  type: "@sntxrr/swamp-triage/investigation",
  version: "2026.10.22.1",
  globalArguments: GlobalArgsSchema,
  upgrades: [
    {
      toVersion: "2026.09.24.1",
      description: "Add the `recent` method; global arguments unchanged",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.09.25.1",
      description:
        "`recent` reports each failure's targetType; global arguments unchanged",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.09.26.1",
      description: "`fetch failed` classifies as unreachable, and a failure " +
        "with no error text as `unrecorded`; global arguments unchanged",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.09.28.1",
      description: "`recent` also lists targets that failed in the window " +
        "and have since recovered; global arguments unchanged",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.10.21.1",
      description: "Tell caller mistakes and never-run schedules apart from " +
        "fleet failures; global arguments unchanged",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
    {
      toVersion: "2026.10.22.1",
      description: "Add the `resolve` method; a workflow failure reports the " +
        "error its run recorded; global arguments unchanged",
      upgradeAttributes: (old: Record<string, unknown>) => old,
    },
  ],
  resources: {
    investigation: {
      description:
        "A classified finding for one investigated model or workflow.",
      schema: InvestigationSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    recent: {
      description: "Every model and workflow that failed within a window, " +
        "whether still failing or since recovered.",
      schema: RecentSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
    resolution: {
      description: "The definitions free alert text most likely names, " +
        "best first.",
      schema: ResolveSchema,
      lifetime: "infinite" as const,
      garbageCollection: 20,
    },
  },
  methods: {
    investigate: {
      description:
        "Investigate why a model or workflow is failing. Resolves the target " +
        "by name, reads the summary reports previous runs left behind, " +
        "reconstructs when it stopped working, and classifies the error into " +
        "a category with a next step. Read-only — never invokes the target.",
      arguments: z.object({
        target: z.string().min(1).describe(
          "Name of the model or workflow to investigate.",
        ),
        kind: z.enum(["auto", "model", "workflow"]).default("auto").describe(
          "Which definitions to search. 'auto' searches models then workflows.",
        ),
        maxVersions: z.number().int().min(1).max(500).default(60).describe(
          "How many recorded runs to walk back through when looking for the " +
            "last success.",
        ),
        placementTag: z.string().optional().describe(
          "key=value tag (e.g. runs-on=primary) naming the workflows this " +
            "datastore runs. A scheduled workflow with no recorded run is " +
            "only reported failing when it carries this tag. Omit to treat " +
            "every scheduled workflow as meant to run here.",
        ),
      }),
      execute: async (
        args: {
          target: string;
          kind: string;
          maxVersions: number;
          placementTag?: string;
        },
        context: Context,
      ) => {
        const repoDir = context.globalArgs.repoDir ?? context.repoDir;
        const placement = parsePlacement(args.placementTag);

        const definitions = await listDefinitions(repoDir, args.kind);
        const matches = definitions.filter((d) => d.name === args.target);
        if (matches.length === 0) {
          // Still an error -- there is no target to write a finding for --
          // but one that names the likely target, so the caller's next try is
          // right instead of another guess.
          const near = rankNames(args.target, definitions);
          throw new Error(
            `No ${args.kind === "auto" ? "model or workflow" : args.kind} ` +
              `named "${args.target}" found in ${repoDir}.` +
              (near.length > 0
                ? ` Closest names: ${
                  near.map((n) => `${n.name} (${n.kind})`).join(", ")
                }.`
                : ` Check the name with \`swamp model list\` or ` +
                  `\`swamp workflow list\`.`),
          );
        }
        const target = matches[0];

        // A model and a workflow may share a name. Investigating one while the
        // operator meant the other, with no sign of it, is the kind of quiet
        // wrong answer this whole model exists to avoid.
        if (matches.length > 1) {
          context.logger.warning(
            'Name "{name}" matches {count} definitions ({kinds}); ' +
              "investigating the {chosen}. Pass kind= to disambiguate.",
            {
              name: args.target,
              count: matches.length,
              kinds: matches.map((m) => m.kind).join(", "),
              chosen: target.kind,
            },
          );
        }

        context.logger.info(
          "Investigating {kind} {name} ({type})",
          { kind: target.kind, name: target.name, type: target.type },
        );

        const dataName = target.kind === "workflow"
          ? "report-swamp-workflow-summary-json"
          : "report-swamp-method-summary-json";

        const latest = await context.dataRepository.findByName(
          target.type,
          target.id,
          dataName,
        );
        if (!latest) {
          const nr = neverRunFinding(target, placement);
          context.logger.info(
            "{name}: no recorded run (scheduled: {schedule}, failing: {failing})",
            {
              name: target.name,
              schedule: target.schedule ?? "no",
              failing: nr.failing,
            },
          );
          return {
            dataHandles: await recordFinding(context, {
              target: target.name,
              targetKind: target.kind,
              targetType: target.type,
              targetId: target.id,
              definitionPath: target.definitionPath,
              investigatedAt: new Date().toISOString(),
              failing: nr.failing,
              currentStatus: "never-run",
              category: nr.classification.category,
              categoryMatched: nr.classification.matched,
              meaning: nr.classification.meaning,
              nextStep: nr.classification.nextStep,
              error: null,
              failingMethod: null,
              rootCauseModel: null,
              redactions: 0,
              redactedKinds: [],
              consecutiveFailures: 0,
              firstFailureAt: null,
              lastSuccessAt: null,
              lastSuccessMethod: null,
              successOutsideWindow: false,
              runsExamined: 0,
              schedule: target.schedule,
              callArgs: [],
              definitionArgs: [],
              summary: nr.summary,
            }),
          };
        }

        // Walk versions newest-first. Reports are written on failure as well
        // as success, so every version is one recorded run.
        const decoder = new TextDecoder();
        const points: RunPoint[] = [];
        // Retained so a workflow failure can be chased into the step that
        // caused it; the workflow report names the step but not its error.
        let headBody: Record<string, unknown> | null = null;
        const floor = Math.max(1, latest.version - args.maxVersions + 1);
        for (let v = latest.version; v >= floor; v--) {
          const meta = await context.dataRepository.findByName(
            target.type,
            target.id,
            dataName,
            v,
          );
          const bytes = await context.dataRepository.getContent(
            target.type,
            target.id,
            dataName,
            v,
          );
          if (!meta || !bytes) continue; // Garbage-collected mid-range.
          let body: Record<string, unknown>;
          try {
            body = JSON.parse(decoder.decode(bytes));
          } catch {
            continue; // A corrupt version must not abort the walk.
          }
          if (points.length === 0) headBody = body;
          points.push({
            version: v,
            createdAt: isoTime(meta.createdAt),
            status: typeof body.status === "string" ? body.status : "unknown",
            methodName: typeof body.methodName === "string"
              ? body.methodName
              : null,
            error: typeof body.error === "string" ? body.error : null,
          });
          // Stop at the first success: it is either the head (nothing is
          // wrong) or the boundary we came for. Older history adds nothing.
          if (body.status === "succeeded") break;
        }

        const timeline = reconstructTimeline(points);
        const head = points[0] ?? null;
        let error = head?.error ?? null;
        let failingMethod = head?.methodName ?? null;
        let rootCauseModel: string | null = null;
        // Whichever run the error came from also says which arguments it took.
        let argBody: Record<string, unknown> | null = headBody;

        // A workflow summary records which step failed and, usually, the
        // error that step raised in this run. That recorded error comes
        // first: it belongs to the failing run, where the step model's latest
        // summary may belong to a later, successful one. Only when the run
        // recorded none is the reference followed to the model the step
        // invoked -- otherwise investigating a workflow by name, which is all
        // an alert gives you, stops one hop short of the actual cause.
        const step = error === null ? firstWorkflowFailure(headBody) : null;
        if (step?.errorMessage) error = step.errorMessage;
        if (step) {
          const { stepModel, stepMethod } = step;
          if (stepModel && error === null) {
            const sub = (await resolveTargets(repoDir, stepModel, "model"))[0];
            if (sub) {
              const subName = "report-swamp-method-summary-json";
              const subBytes = await context.dataRepository.getContent(
                sub.type,
                sub.id,
                subName,
              );
              if (subBytes) {
                try {
                  const subBody = JSON.parse(decoder.decode(subBytes));
                  if (typeof subBody.error === "string") {
                    error = subBody.error;
                    rootCauseModel = stepModel;
                    argBody = subBody;
                  }
                } catch {
                  // Fall through: the step name alone is still worth reporting.
                }
              }
            }
          }
          if (stepModel) {
            failingMethod = stepMethod
              ? `${stepModel} → ${stepMethod}`
              : stepModel;
          }
        }

        // Classify against the ORIGINAL text, then redact. Doing it the other
        // way round would let redaction eat the evidence a rule matches on and
        // silently downgrade a recognised failure to `unknown`.
        const failing = timeline.currentStatus !== "succeeded";
        const classification = classifyError(error, failing);
        const redaction = redactSecrets(error);
        error = error === null ? null : redaction.text;
        if (redaction.count > 0) {
          context.logger.warning(
            "Redacted {count} secret value(s) ({kinds}) from {name}'s error " +
              "before recording the finding",
            {
              count: redaction.count,
              kinds: redaction.kinds.join(", "),
              name: target.name,
            },
          );
        }

        const investigatedAt = isoTime(latest.createdAt);
        const names = (v: unknown) =>
          Array.isArray(v) ? v.filter((x) => typeof x === "string") : [];
        const callArgs = names(argBody?.methodArgs);
        const definitionArgs = names(argBody?.globalArgs);
        const summary = buildSummary(
          target,
          timeline,
          classification,
          error,
          failingMethod,
          rootCauseModel,
          { call: callArgs, definition: definitionArgs },
        );

        context.logger.info(
          "{name}: {status}, category {category}",
          {
            name: target.name,
            status: timeline.currentStatus,
            category: classification.category,
          },
        );

        const finding = {
          target: target.name,
          targetKind: target.kind,
          targetType: target.type,
          targetId: target.id,
          definitionPath: target.definitionPath,
          investigatedAt,
          failing,
          currentStatus: timeline.currentStatus,
          category: classification.category,
          categoryMatched: classification.matched,
          meaning: classification.meaning,
          nextStep: classification.nextStep,
          error,
          failingMethod,
          rootCauseModel,
          redactions: redaction.count,
          redactedKinds: redaction.kinds,
          consecutiveFailures: timeline.consecutiveFailures,
          firstFailureAt: timeline.firstFailure?.createdAt ?? null,
          lastSuccessAt: timeline.lastSuccess?.createdAt ?? null,
          lastSuccessMethod: timeline.lastSuccess?.methodName ?? null,
          successOutsideWindow: timeline.successOutsideWindow,
          runsExamined: timeline.examined,
          schedule: target.schedule,
          callArgs,
          definitionArgs,
          summary,
        };

        return { dataHandles: await recordFinding(context, finding) };
      },
    },
    recent: {
      description:
        "List every model and workflow that failed within the last " +
        "`withinHours` -- still failing first, then those that have since " +
        "recovered (failing=false, with recoveredAt) -- newest first, each " +
        "with its instance name, failing step and error category. Needs no " +
        "target name -- use it when an alert names nothing, then " +
        "`investigate` the one that matters. Read-only.",
      arguments: z.object({
        // No schema maximum: an over-wide request is capped in `execute` with
        // a warning. A refusal fails the investigator's own run, which then
        // shows up in the next `recent` as a failure nobody else caused.
        withinHours: z.number().int().min(1).default(24).describe(
          `How far back to look for failed runs. Values above ` +
            `${MAX_WINDOW_HOURS} are capped at ${MAX_WINDOW_HOURS}.`,
        ),
        kind: z.enum(["auto", "model", "workflow"]).default("auto").describe(
          "Which targets to list. 'auto' lists models and workflows.",
        ),
        limit: z.number().int().min(1).max(100).default(20).describe(
          "Maximum failures to list; the rest are counted, not dropped.",
        ),
        maxVersions: z.number().int().min(1).max(500).default(60).describe(
          "How many earlier runs to read per recovered target when looking " +
            "for a failure inside the window.",
        ),
        placementTag: z.string().optional().describe(
          "key=value tag (e.g. runs-on=primary) naming the workflows this " +
            "datastore runs; only those are checked for a schedule that has " +
            "never fired. Omit to check every scheduled workflow.",
        ),
      }),
      execute: async (
        args: {
          withinHours: number;
          kind: string;
          limit: number;
          maxVersions: number;
          placementTag?: string;
        },
        context: Context,
      ) => {
        const now = Date.now();
        const requestedHours = args.withinHours;
        const hours = Math.min(requestedHours, MAX_WINDOW_HOURS);
        if (hours < requestedHours) {
          context.logger.warning(
            "withinHours {requested} is over the {max}h maximum; using {max}h",
            { requested: requestedHours, max: MAX_WINDOW_HOURS },
          );
        }
        const placement = parsePlacement(args.placementTag);
        context.logger.info(
          "Listing {kind} targets that failed in the last {hours}h",
          { kind: args.kind, hours },
        );
        const repoDir = context.globalArgs.repoDir ?? context.repoDir;
        const definitions = await listDefinitions(repoDir, "auto");
        const { heads, skipped } = await readSummaryHeads(context);
        if (skipped > 0) {
          context.logger.warning(
            "Skipped {count} summary report(s) that could not be read",
            { count: skipped },
          );
        }

        const { recovered, truncated } = await readRecoveredFailures(
          context,
          heads,
          now,
          hours,
          args.kind,
          args.maxVersions,
        );
        if (truncated > 0) {
          context.logger.warning(
            "{count} recovered target(s) have more than {max} runs in the " +
              "window; older failures of theirs were not read",
            { count: truncated, max: args.maxVersions },
          );
        }
        const sel = selectRecentFailures(
          heads,
          now,
          hours,
          args.kind,
          args.limit,
          recovered,
          { selfType: MODEL_TYPE, definitions, placement },
        );
        const redactions = sel.failures.reduce((n, f) => n + f.redactions, 0);
        if (redactions > 0) {
          context.logger.warning(
            "Redacted {count} secret value(s) from recorded errors before " +
              "recording the list",
            { count: redactions },
          );
        }
        context.logger.info(
          "{failing} failing in the last {hours}h ({stale} older, {own} the " +
            "investigator's own, {never} scheduled never-run), from " +
            "{examined} summaries",
          {
            failing: sel.failures.length + sel.omitted,
            hours,
            stale: sel.staleFailing,
            own: sel.failures.filter((f) => f.selfInflicted).length,
            never: sel.scheduledNeverRun.length,
            examined: heads.length,
          },
        );

        // One stable instance, overwritten each run, so a workflow can read
        // `data.latest('triage', 'recent')` the way it reads `current`.
        const handle = await context.writeResource("recent", "recent", {
          checkedAt: new Date(now).toISOString(),
          withinHours: hours,
          since: new Date(now - hours * 3_600_000).toISOString(),
          kind: args.kind,
          summariesExamined: heads.length,
          failures: sel.failures,
          omitted: sel.omitted,
          staleFailing: sel.staleFailing,
          historyTruncated: truncated,
          requestedHours,
          scheduledNeverRun: sel.scheduledNeverRun,
          placementTag: placement
            ? `${placement.key}=${placement.value}`
            : null,
          summary: buildRecentSummary(sel, hours, requestedHours),
        });
        return { dataHandles: [handle] };
      },
    },
    resolve: {
      description:
        "Map free alert text to the model and workflow names it most likely " +
        "means -- for an alert that does not name its target. Scores token " +
        "overlap with each definition's name, type, tags and description and " +
        "returns the top matches with kind, runs-on tag and score. Then " +
        "`investigate` the first. Read-only.",
      arguments: z.object({
        text: z.string().min(1).describe(
          "Free alert text, e.g. a notification title or a step name.",
        ),
        kind: z.enum(["auto", "model", "workflow"]).default("auto").describe(
          "Which definitions to search. 'auto' searches both.",
        ),
        limit: z.number().int().min(1).max(20).default(5).describe(
          "Most matches to return.",
        ),
      }),
      execute: async (
        args: { text: string; kind: string; limit: number },
        context: Context,
      ) => {
        const repoDir = context.globalArgs.repoDir ?? context.repoDir;
        const definitions = await listDefinitions(repoDir, args.kind);
        // The text is echoed back into data, and an alert body can carry a
        // secret value. A secret never helps match a name, so redact first.
        const text = redactSecrets(args.text).text;
        const matches = resolveText(text, definitions, args.limit);
        context.logger.info(
          "Resolved {count} match(es) for {text} from {examined} definitions",
          { count: matches.length, text, examined: definitions.length },
        );
        // One stable instance, like `recent`. No match is an answer, not an
        // error: a failed run here would read as a fleet failure in `recent`.
        const handle = await context.writeResource("resolution", "resolve", {
          resolvedAt: new Date().toISOString(),
          text,
          tokens: resolveTokens(text),
          kind: args.kind,
          definitionsExamined: definitions.length,
          matches,
          summary: buildResolveSummary(text, matches),
        });
        return { dataHandles: [handle] };
      },
    },
  },
};
