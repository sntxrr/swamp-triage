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

/**
 * Ordered classification rules; the first match wins.
 *
 * Order matters where categories overlap. Auth precedes the generic HTTP
 * buckets because a 403 carrying "invalid credentials" is an auth problem
 * first and an HTTP status second.
 */
const RULES: Rule[] = [
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
    meaning: "The remote never answered. This is a network, DNS or host-down " +
      "problem, not a credential problem.",
    nextStep: "Confirm the host is up and routable from wherever swamp runs, " +
      "including any tailnet or VPN the address depends on.",
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
 * @param error The error text recorded by the summary report.
 * @returns The matched category with its meaning and next step.
 */
export function classifyError(
  error: string | null | undefined,
): Classification {
  const text = (error ?? "").trim();
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
    const key = m[1];
    let value = m[2].trim();
    if (value === "" || value.startsWith(">") || value.startsWith("|")) {
      continue;
    }
    // Strip an inline comment only when the value is not quoted.
    if (!/^["']/.test(value)) value = value.replace(/\s+#.*$/, "").trim();
    // Unwrap matching surrounding quotes.
    const q = /^(["'])([\s\S]*)\1$/.exec(value);
    if (q) value = q[2];
    if (value !== "") out[key] = value;
  }
  return out;
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
      if (doc.name !== target) continue;
      const id = doc.id;
      if (!id) continue;
      const type = k === "workflow" ? "workflow" : doc.type;
      if (!type) continue;
      matches.push({
        name: target,
        kind: k,
        type,
        id,
        definitionPath: path.startsWith(repoDir + "/")
          ? path.slice(repoDir.length + 1)
          : path,
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
}

/** One target whose most recent run failed. */
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
}

/** What `recent` found, before it is recorded. */
export interface RecentSelection {
  failures: RecentFailure[];
  /** Failing targets inside the window beyond `limit`. */
  omitted: number;
  /**
   * Targets still failing whose last run is older than the window -- a
   * weekly job broken for days. Counted so a narrow window cannot make them
   * read as healthy; widen the window to list them.
   */
  staleFailing: number;
}

/**
 * Describe one failing summary: where it broke, and why.
 *
 * A workflow summary names the failing step but carries no error, so the
 * step's model is looked up among the method summaries the same query
 * already returned -- the same hop `investigate` makes, without a second
 * read.
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

  if (error === null && Array.isArray(body.failures)) {
    const first = (body.failures as Record<string, unknown>[])[0];
    const stepModel = typeof first?.modelName === "string"
      ? first.modelName
      : null;
    const stepMethod = typeof first?.methodName === "string"
      ? first.methodName
      : null;
    if (stepModel) {
      const sub = methodBodies.get(stepModel);
      if (typeof sub?.error === "string") {
        error = sub.error;
        rootCauseModel = stepModel;
      }
      failingMethod = stepMethod ? `${stepModel} → ${stepMethod}` : stepModel;
    }
  }

  // Classify before redacting, for the reason given in `investigate`.
  const c = classifyError(error);
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
  };
}

/**
 * Pick the targets whose most recent run failed within the window.
 *
 * Anything not an explicit success counts as a failure, as in
 * `reconstructTimeline`. Results are newest first, so the thing that broke
 * most recently -- usually the one an alert is about -- leads.
 *
 * @param heads Latest summary per target, any order.
 * @param nowMs Reference time in epoch milliseconds.
 * @param withinHours Window size.
 * @param kind "model", "workflow", or "auto" for both.
 * @param limit Maximum failures to return.
 */
export function selectRecentFailures(
  heads: SummaryHead[],
  nowMs: number,
  withinHours: number,
  kind: string,
  limit: number,
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

  return {
    failures: inWindow.slice(0, limit).map((h) =>
      describeFailure(h, methodBodies)
    ),
    omitted: Math.max(0, inWindow.length - limit),
    staleFailing,
  };
}

/** Render a `recent` result as a paragraph for a notification or chat. */
export function buildRecentSummary(
  sel: RecentSelection,
  withinHours: number,
): string {
  const lines: string[] = [];
  if (sel.failures.length === 0) {
    lines.push(`Nothing has failed in the last ${withinHours}h.`);
  } else {
    lines.push(
      `${sel.failures.length + sel.omitted} target(s) failed in the last ` +
        `${withinHours}h, newest first:`,
    );
    for (const f of sel.failures) {
      const where = f.failingMethod ? ` at \`${f.failingMethod}\`` : "";
      // A model's type is what a run-history line names; show it so the two
      // can be matched by eye.
      const what = f.kind === "model" ? `model ${f.targetType}` : f.kind;
      lines.push(
        `- ${f.target} (${what})${where} — **${f.category}**, ${f.failedAt}`,
      );
    }
    if (sel.omitted > 0) {
      lines.push(`- …and ${sel.omitted} more; raise \`limit\` to list them.`);
    }
    lines.push(
      "Run `investigate` on one of these for its full timeline and next step.",
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
  })),
  /** Failing targets inside the window left out by `limit`. */
  omitted: z.number(),
  /** Targets still failing whose last run predates the window. */
  staleFailing: z.number(),
  /** Plain-language list, suitable for a notification body. */
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
  // `current` and `recent` are the stable handles. A target with one of those
  // names would overwrite the handle with a per-target finding, so its first
  // character is encoded too. Still injective: a literal `%` became `%25`.
  if (RESERVED_INSTANCES.has(encoded)) {
    return `%${encoded.charCodeAt(0).toString(16).toUpperCase()}` +
      encoded.slice(1);
  }
  return encoded;
}

/** Instance names the model writes to on every run, whatever the target. */
const RESERVED_INSTANCES = new Set(["current", "recent"]);

/** Render the investigation as a paragraph an operator can act on directly. */
function buildSummary(
  t: ResolvedTarget,
  tl: Timeline,
  c: Classification,
  error: string | null,
  failingMethod: string | null,
  rootCauseModel: string | null,
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
  parts.push(`Next step: ${c.nextStep}`);
  return parts.join("\n\n");
}

export const model = {
  type: "@sntxrr/swamp-triage/investigation",
  version: "2026.09.25.1",
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
      description:
        "Every model and workflow whose most recent run failed within a window.",
      schema: RecentSchema,
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
      }),
      execute: async (
        args: { target: string; kind: string; maxVersions: number },
        context: Context,
      ) => {
        const repoDir = context.globalArgs.repoDir ?? context.repoDir;

        const matches = await resolveTargets(repoDir, args.target, args.kind);
        if (matches.length === 0) {
          throw new Error(
            `No ${args.kind === "auto" ? "model or workflow" : args.kind} ` +
              `named "${args.target}" found in ${repoDir}. Check the name ` +
              `with \`swamp model list\` or \`swamp workflow list\`.`,
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
          throw new Error(
            `No summary reports recorded for ${target.kind} ` +
              `"${target.name}". It may never have run in this repo, or its ` +
              `report data may have aged out of retention.`,
          );
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

        // A workflow summary records which step failed, not why. The error
        // lives on the model that step invoked, so follow the reference --
        // otherwise investigating a workflow by name, which is all an alert
        // gives you, stops one hop short of the actual cause.
        if (error === null && Array.isArray(headBody?.failures)) {
          const failures = headBody.failures as Record<string, unknown>[];
          const first = failures[0];
          const stepModel = typeof first?.modelName === "string"
            ? first.modelName
            : null;
          const stepMethod = typeof first?.methodName === "string"
            ? first.methodName
            : null;
          if (stepModel) {
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
                  }
                } catch {
                  // Fall through: the step name alone is still worth reporting.
                }
              }
            }
            failingMethod = stepMethod
              ? `${stepModel} → ${stepMethod}`
              : stepModel;
          }
        }

        // Classify against the ORIGINAL text, then redact. Doing it the other
        // way round would let redaction eat the evidence a rule matches on and
        // silently downgrade a recognised failure to `unknown`.
        const classification = classifyError(error);
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
        const failing = timeline.currentStatus !== "succeeded";

        const investigatedAt = isoTime(latest.createdAt);
        const summary = buildSummary(
          target,
          timeline,
          classification,
          error,
          failingMethod,
          rootCauseModel,
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
          summary,
        };

        // Two instances of the same finding, deliberately.
        //
        // The per-target instance keeps history: investigate the same thing
        // twice and the versions are comparable to each other. Its name is
        // sanitized, because swamp rejects `/` in a data name and a bundled
        // workflow's name is required to be collective-scoped.
        //
        // `current` is the stable handle a workflow can reference without
        // knowing the target's name at all -- `data.latest('triage',
        // 'current')`. Deriving the instance from the target meant the
        // reference had to reproduce the sanitization in CEL, which is both
        // awkward and one more place for the two to drift apart.
        //
        // Concurrent investigations race on `current`; the per-target instance
        // is the one to read when that matters.
        const perTarget = await context.writeResource(
          "investigation",
          sanitizeInstanceName(target.name),
          finding,
        );
        const current = await context.writeResource(
          "investigation",
          "current",
          finding,
        );

        return { dataHandles: [perTarget, current] };
      },
    },
    recent: {
      description:
        "List every model and workflow whose most recent run failed within " +
        "the last `withinHours`, newest first, each with its failing step and " +
        "error category. Needs no target name -- use it when an alert names " +
        "nothing, then `investigate` the one that matters. Read-only.",
      arguments: z.object({
        withinHours: z.number().int().min(1).max(720).default(24).describe(
          "How far back to look for failed runs.",
        ),
        kind: z.enum(["auto", "model", "workflow"]).default("auto").describe(
          "Which targets to list. 'auto' lists models and workflows.",
        ),
        limit: z.number().int().min(1).max(100).default(20).describe(
          "Maximum failures to list; the rest are counted, not dropped.",
        ),
      }),
      execute: async (
        args: { withinHours: number; kind: string; limit: number },
        context: Context,
      ) => {
        const now = Date.now();
        context.logger.info(
          "Listing {kind} targets that failed in the last {hours}h",
          { kind: args.kind, hours: args.withinHours },
        );
        const { heads, skipped } = await readSummaryHeads(context);
        if (skipped > 0) {
          context.logger.warning(
            "Skipped {count} summary report(s) that could not be read",
            { count: skipped },
          );
        }

        const sel = selectRecentFailures(
          heads,
          now,
          args.withinHours,
          args.kind,
          args.limit,
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
          "{failing} failing in the last {hours}h ({stale} older), from " +
            "{examined} summaries",
          {
            failing: sel.failures.length + sel.omitted,
            hours: args.withinHours,
            stale: sel.staleFailing,
            examined: heads.length,
          },
        );

        // One stable instance, overwritten each run, so a workflow can read
        // `data.latest('triage', 'recent')` the way it reads `current`.
        const handle = await context.writeResource("recent", "recent", {
          checkedAt: new Date(now).toISOString(),
          withinHours: args.withinHours,
          since: new Date(now - args.withinHours * 3_600_000).toISOString(),
          kind: args.kind,
          summariesExamined: heads.length,
          failures: sel.failures,
          omitted: sel.omitted,
          staleFailing: sel.staleFailing,
          summary: buildRecentSummary(sel, args.withinHours),
        });
        return { dataHandles: [handle] };
      },
    },
  },
};
