import { assertEquals } from "jsr:@std/assert@1";
import {
  buildRecentSummary,
  buildResolveSummary,
  classifyError,
  describeFailure,
  firstWorkflowFailure,
  isCallerError,
  isQuickRetry,
  listDefinitions,
  MAX_WINDOW_HOURS,
  METHOD_SUMMARY,
  model,
  MODEL_TYPE,
  parsePlacement,
  placedHere,
  rankNames,
  readDescription,
  readNestedScalars,
  readRecoveredFailures,
  readSummaryHeads,
  readTopLevelScalars,
  reconstructTimeline,
  redactSecrets,
  resolveTargets,
  resolveText,
  resolveTokens,
  type RunPoint,
  sanitizeInstanceName,
  selectRecentFailures,
  type SummaryHead,
  WORKFLOW_SUMMARY,
} from "./swamp_triage.ts";

/**
 * The classifier's job is to send an operator to the right place. These cover
 * the distinctions that actually change where you look -- especially auth vs
 * unreachable, which read almost identically in a notification and lead in
 * opposite directions.
 *
 * Error strings are modelled on real ones but carry only documentation
 * addresses (RFC 5737 TEST-NET-1) and no operator's real hosts or accounts.
 */

Deno.test("classify: a 403 with invalid credentials is auth, not http noise", () => {
  const c = classifyError(
    'UniFi login to 192.0.2.1 failed (403): {"message":"Invalid username or ' +
      'password","code":"AUTHENTICATION_FAILED_INVALID_CREDENTIALS"}',
  );
  assertEquals(c.category, "auth");
  assertEquals(c.matched, true);
});

Deno.test("classify: a refused connection is unreachable, not auth", () => {
  // The distinction that matters: nothing answered, so no credential was
  // ever judged. Sending someone to the vault here wastes the outage.
  const c = classifyError("connect ECONNREFUSED 192.0.2.1:443");
  assertEquals(c.category, "unreachable");
});

Deno.test("classify: expired token is auth", () => {
  assertEquals(
    classifyError("401 Unauthorized: token has expired").category,
    "auth",
  );
});

Deno.test("classify: timeout is distinct from unreachable", () => {
  const c = classifyError("request to https://192.0.2.5 failed: ETIMEDOUT");
  assertEquals(c.category, "timeout");
});

Deno.test("classify: 429 is rate_limit, not auth", () => {
  assertEquals(
    classifyError("HTTP 429 Too Many Requests").category,
    "rate_limit",
  );
});

Deno.test("classify: certificate problems surface as tls", () => {
  const c = classifyError("self-signed certificate in certificate chain");
  assertEquals(c.category, "tls");
});

Deno.test("classify: argument validation is config, not a remote fault", () => {
  const c = classifyError(
    "Unknown input(s): _comment. Valid inputs are: devices, host",
  );
  assertEquals(c.category, "config");
});

Deno.test("classify: an unrecognised error is unknown, never guessed", () => {
  // Filing this under a plausible category would send the operator the wrong
  // way with false confidence. Being visibly unrecognised is the useful answer.
  const c = classifyError("quantum flux desynchronisation in the widget array");
  assertEquals(c.category, "unknown");
  assertEquals(c.matched, false);
});

Deno.test("classify: no error is 'none', not 'unknown'", () => {
  assertEquals(classifyError(null).category, "none");
  assertEquals(classifyError("   ").category, "none");
});

Deno.test("classify: a fetch that never connected is unreachable", () => {
  // The runtime's generic message when no connection was made. It names no
  // code, so without its own pattern it fell through to `unknown`.
  const c = classifyError(
    "Apprise POST http://apprise.example:8000/notify/k failed: TypeError: fetch failed",
  );
  assertEquals(c.category, "unreachable");
  assertEquals(c.matched, true);
});

Deno.test("classify: a specific cause beside 'fetch failed' wins over it", () => {
  // `fetch failed` is only the wrapper; the cause it carries is the more
  // specific signal, whichever rule it belongs to.
  const cases: [string, string][] = [
    [
      "TypeError: fetch failed (cause: connect ETIMEDOUT 192.0.2.1:443)",
      "timeout",
    ],
    ["TypeError: fetch failed [cause: UND_ERR_CONNECT_TIMEOUT]", "timeout"],
    ["TypeError: fetch failed: certificate has expired", "tls"],
    [
      "TypeError: fetch failed: connect ECONNREFUSED 192.0.2.1:443",
      "unreachable",
    ],
  ];
  for (const [text, want] of cases) {
    assertEquals(classifyError(text).category, want, text);
  }
});

Deno.test("classify: a failed run with no error text is unrecorded, not none", () => {
  // `none` means "not failing"; saying that beside status=failed is a lie.
  // Nor is it `unknown`, which means text was present and matched no rule.
  for (const error of [null, undefined, "", "   "]) {
    const c = classifyError(error, true);
    assertEquals(c.category, "unrecorded", String(error));
    assertEquals(c.matched, false);
  }
  // Negative control: a target that is not failing is still `none`.
  assertEquals(classifyError(null, false).category, "none");
  assertEquals(classifyError("").category, "none");
  // Text that is present classifies the same whether or not it failed.
  assertEquals(classifyError("HTTP 429", true).category, "rate_limit");
});

/* ---------------------------- timeline ---------------------------- */

const at = (
  v: number,
  iso: string,
  status: string,
  error?: string,
): RunPoint => ({
  version: v,
  createdAt: iso,
  status,
  methodName: "drift",
  error: error ?? null,
});

Deno.test("timeline: finds the boundary between last success and first failure", () => {
  // The shape of the real incident this model was built from: green all day,
  // then a credential rotation lands between two scheduled runs.
  const tl = reconstructTimeline([
    at(304, "2026-08-04T18:04:05Z", "failed", "403"),
    at(303, "2026-08-04T17:47:06Z", "failed", "403"),
    at(302, "2026-08-04T17:40:01Z", "failed", "403"),
    at(301, "2026-08-04T17:35:06Z", "failed", "403"),
    at(300, "2026-08-04T17:04:05Z", "succeeded"),
  ]);
  assertEquals(tl.currentStatus, "failed");
  assertEquals(tl.consecutiveFailures, 4);
  assertEquals(tl.firstFailure?.createdAt, "2026-08-04T17:35:06Z");
  assertEquals(tl.lastSuccess?.createdAt, "2026-08-04T17:04:05Z");
  assertEquals(tl.successOutsideWindow, false);
});

Deno.test("timeline: a healthy target reports no failures", () => {
  const tl = reconstructTimeline([
    at(300, "2026-08-04T17:04:05Z", "succeeded"),
  ]);
  assertEquals(tl.currentStatus, "succeeded");
  assertEquals(tl.consecutiveFailures, 0);
  assertEquals(tl.firstFailure, null);
  assertEquals(tl.successOutsideWindow, false);
});

Deno.test("timeline: all-failed history flags the boundary as outside the window", () => {
  // Reporting the oldest retained failure as "first failure" here would be a
  // fabricated start time. The caller must be able to tell the difference
  // between "it broke then" and "we did not look far enough back".
  const tl = reconstructTimeline([
    at(9, "2026-08-04T03:00:00Z", "failed", "403"),
    at(8, "2026-08-04T02:00:00Z", "failed", "403"),
  ]);
  assertEquals(tl.consecutiveFailures, 2);
  assertEquals(tl.lastSuccess, null);
  assertEquals(tl.successOutsideWindow, true);
});

Deno.test("timeline: a success after a recovered blip is still the last success", () => {
  const tl = reconstructTimeline([
    at(12, "2026-08-04T05:00:00Z", "failed", "boom"),
    at(11, "2026-08-04T04:00:00Z", "succeeded"),
    at(10, "2026-08-04T03:00:00Z", "failed", "boom"),
  ]);
  assertEquals(tl.consecutiveFailures, 1);
  assertEquals(tl.lastSuccess?.version, 11);
  assertEquals(tl.firstFailure?.version, 12);
});

Deno.test("timeline: empty history is unknown, not healthy", () => {
  const tl = reconstructTimeline([]);
  assertEquals(tl.currentStatus, "unknown");
  assertEquals(tl.examined, 0);
});

Deno.test("timeline: a non-succeeded status other than 'failed' counts as failure", () => {
  // Statuses evolve; anything that is not an explicit success must not be
  // silently read as one.
  const tl = reconstructTimeline([
    at(5, "2026-08-04T05:00:00Z", "cancelled"),
    at(4, "2026-08-04T04:00:00Z", "succeeded"),
  ]);
  assertEquals(tl.consecutiveFailures, 1);
  assertEquals(tl.lastSuccess?.version, 4);
});

/* ------------------------ target resolution ----------------------- */

/** Build a throwaway repo with the given definition files. */
async function fixtureRepo(
  files: Record<string, string>,
): Promise<string> {
  const dir = await Deno.makeTempDir({ prefix: "swamp-triage-test-" });
  for (const [rel, body] of Object.entries(files)) {
    const path = `${dir}/${rel}`;
    await Deno.mkdir(path.slice(0, path.lastIndexOf("/")), { recursive: true });
    await Deno.writeTextFile(path, body);
  }
  return dir;
}

Deno.test("resolve: finds a model by name and reports its type and id", async () => {
  const dir = await fixtureRepo({
    "models/@acme/thing/abc.yaml":
      "type: '@acme/thing'\nid: abc-123\nname: widget\n",
  });
  try {
    const found = await resolveTargets(dir, "widget", "auto");
    assertEquals(found.length, 1);
    assertEquals(found[0].kind, "model");
    assertEquals(found[0].type, "@acme/thing");
    assertEquals(found[0].id, "abc-123");
    // Path is repo-relative so a finding never leaks the investigator's
    // home directory into a notification.
    assertEquals(found[0].definitionPath, "models/@acme/thing/abc.yaml");
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("resolve: workflows carry the literal 'workflow' repo type", async () => {
  const dir = await fixtureRepo({
    "workflows/wf.yaml": "id: wf-1\nname: nightly\n",
  });
  try {
    const found = await resolveTargets(dir, "nightly", "auto");
    assertEquals(found[0].kind, "workflow");
    assertEquals(found[0].type, "workflow");
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("resolve: a name shared by a model and a workflow returns both", async () => {
  // The caller warns on this. Returning only the first would investigate a
  // different thing than the operator named, with no sign of it.
  const dir = await fixtureRepo({
    "models/@acme/thing/a.yaml": "type: '@acme/thing'\nid: m-1\nname: sync\n",
    "workflows/b.yaml": "id: w-1\nname: sync\n",
  });
  try {
    const found = await resolveTargets(dir, "sync", "auto");
    assertEquals(found.length, 2);
    assertEquals(found.map((f) => f.kind), ["model", "workflow"]);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("resolve: kind filter narrows the search", async () => {
  const dir = await fixtureRepo({
    "models/@acme/thing/a.yaml": "type: '@acme/thing'\nid: m-1\nname: sync\n",
    "workflows/b.yaml": "id: w-1\nname: sync\n",
  });
  try {
    const found = await resolveTargets(dir, "sync", "workflow");
    assertEquals(found.length, 1);
    assertEquals(found[0].id, "w-1");
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("resolve: an unparseable neighbour does not abort the search", async () => {
  const dir = await fixtureRepo({
    "models/@acme/thing/broken.yaml": "{{{ not: [valid yaml\n",
    "models/@acme/thing/good.yaml":
      "type: '@acme/thing'\nid: ok-1\nname: widget\n",
  });
  try {
    const found = await resolveTargets(dir, "widget", "auto");
    assertEquals(found.length, 1);
    assertEquals(found[0].id, "ok-1");
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("resolve: a missing directory is not an error", async () => {
  // A repo need not have both models/ and workflows/.
  const dir = await fixtureRepo({ "workflows/b.yaml": "id: w-1\nname: x\n" });
  try {
    assertEquals((await resolveTargets(dir, "nope", "auto")).length, 0);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("resolve: a definition with no id is skipped, not half-returned", async () => {
  const dir = await fixtureRepo({
    "models/@acme/thing/a.yaml": "type: '@acme/thing'\nname: widget\n",
  });
  try {
    assertEquals((await resolveTargets(dir, "widget", "auto")).length, 0);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

/* --------------------- top-level scalar reader -------------------- */

Deno.test("scalars: reads plain top-level fields", () => {
  const d = readTopLevelScalars(
    "type: '@acme/thing'\nid: abc-123\nname: widget\n",
  );
  assertEquals(d.type, "@acme/thing");
  assertEquals(d.id, "abc-123");
  assertEquals(d.name, "widget");
});

Deno.test("scalars: block-scalar content cannot be mistaken for a field", () => {
  // The failure this guards: a description whose body contains lines that look
  // exactly like top-level keys. Block content is always indented, so a
  // column-zero rule skips it -- but only if the rule is actually column-zero.
  const d = readTopLevelScalars(
    [
      "id: real-id",
      "name: real-name",
      "description: >-",
      "  Invoke from cron with:",
      "    swamp workflow run thing --repo-dir <repo>",
      "  name: decoy",
      "  id: decoy-id",
      "  type: '@decoy/type'",
      "tags: {}",
    ].join("\n"),
  );
  assertEquals(d.id, "real-id");
  assertEquals(d.name, "real-name");
  assertEquals(d.type, undefined);
});

Deno.test("scalars: the block-scalar key itself is not captured as a value", () => {
  const d = readTopLevelScalars("description: >-\n  text\nname: x\n");
  assertEquals(d.description, undefined);
  assertEquals(d.name, "x");
});

Deno.test("scalars: literal block scalars are skipped too", () => {
  const d = readTopLevelScalars("script: |\n  echo hi\nname: x\n");
  assertEquals(d.script, undefined);
  assertEquals(d.name, "x");
});

Deno.test("scalars: quoted values keep inner '#' but bare values drop comments", () => {
  const d = readTopLevelScalars(
    "name: widget # trailing note\ntoken: 'abc#notacomment'\n",
  );
  assertEquals(d.name, "widget");
  assertEquals(d.token, "abc#notacomment");
});

Deno.test("scalars: comment and blank lines are ignored", () => {
  const d = readTopLevelScalars("# a comment\n\nname: x\n");
  assertEquals(d.name, "x");
  assertEquals(Object.keys(d), ["name"]);
});

Deno.test("scalars: nested mapping values do not leak upward", () => {
  const d = readTopLevelScalars(
    "globalArguments:\n  host: 192.0.2.1\n  name: nested-decoy\nname: outer\n",
  );
  assertEquals(d.name, "outer");
  assertEquals(d.host, undefined);
});

/* --------------------------- redaction ---------------------------- */

Deno.test("redact: the motivating error survives completely intact", () => {
  // The whole point of the tool. This error carries no secret VALUE -- only
  // the words "username or password" -- and mangling it would destroy the
  // most diagnostic sentence in the finding while protecting nothing.
  const original =
    'UniFi login to 192.0.2.1 failed (403): {"message":"Invalid username or ' +
    'password","code":"AUTHENTICATION_FAILED_INVALID_CREDENTIALS"}';
  const r = redactSecrets(original);
  assertEquals(r.count, 0);
  assertEquals(r.text, original);
  // And it must still classify as auth afterwards.
  assertEquals(classifyError(r.text).category, "auth");
});

Deno.test("redact: keyed values lose the value, keep the key", () => {
  const r = redactSecrets("connect failed: password=hunter2 for user admin");
  assertEquals(r.text, "connect failed: password=[redacted] for user admin");
  assertEquals(r.kinds, ["keyed-value"]);
  // The surrounding context survives, so the error is still readable.
  assertEquals(r.text.includes("for user admin"), true);
});

Deno.test("redact: quoted JSON secrets are caught", () => {
  const r = redactSecrets('{"api_key": "abcd1234efgh", "region": "us-west-2"}');
  assertEquals(r.text.includes("abcd1234efgh"), false);
  assertEquals(r.text.includes("us-west-2"), true);
});

Deno.test("redact: credentials embedded in a URL", () => {
  const r = redactSecrets(
    "failed to reach https://admin:s3cr3t@example.com/api",
  );
  assertEquals(
    r.text,
    "failed to reach https://admin:[redacted]@example.com/api",
  );
  assertEquals(r.kinds.includes("url-credentials"), true);
});

Deno.test("redact: a JWT is removed wholesale", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.abcdefghijk";
  const r = redactSecrets(`401 rejected token ${jwt} at gateway`);
  assertEquals(r.text.includes(jwt), false);
  assertEquals(r.text.includes("at gateway"), true);
  assertEquals(classifyError(r.text).category, "auth");
});

Deno.test("redact: provider-shaped tokens are recognised on sight", () => {
  const r = redactSecrets(
    "denied for AKIAIOSFODNN7EXAMPLE and ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345",
  );
  assertEquals(r.text.includes("AKIAIOSFODNN7EXAMPLE"), false);
  assertEquals(r.text.includes("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"), false);
  assertEquals(r.count, 2);
});

Deno.test("redact: a private key block goes entirely", () => {
  const r = redactSecrets(
    "ssh failed:\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\nAAAA\n-----END OPENSSH PRIVATE KEY-----\nexiting",
  );
  assertEquals(r.text.includes("b3BlbnNzaC1rZXk"), false);
  assertEquals(r.text.includes("[redacted:private-key]"), true);
  assertEquals(r.text.includes("exiting"), true);
});

Deno.test("redact: an authorization header value is blanked", () => {
  const r = redactSecrets("sent Authorization: Bearer abc123def456 -> 403");
  assertEquals(r.text.includes("abc123def456"), false);
  assertEquals(r.text.includes("403"), true);
});

Deno.test("redact: clean text is returned untouched with no false positives", () => {
  const clean = "connect ECONNREFUSED 192.0.2.1:443";
  const r = redactSecrets(clean);
  assertEquals(r.text, clean);
  assertEquals(r.count, 0);
  assertEquals(r.kinds, []);
});

Deno.test("redact: null and empty are safe", () => {
  assertEquals(redactSecrets(null).text, "");
  assertEquals(redactSecrets(null).count, 0);
  assertEquals(redactSecrets("").count, 0);
});

Deno.test("redact: classification is never degraded by redaction", () => {
  // Redaction runs after classification in the method for exactly this
  // reason, but the rules should not eat classifier evidence even so.
  const cases: [string, string][] = [
    ["403 Forbidden: token=abc123", "auth"],
    ["ECONNREFUSED with password=hunter2 in config", "unreachable"],
    ["429 rate limit, api_key=deadbeefcafe", "rate_limit"],
  ];
  for (const [text, want] of cases) {
    assertEquals(classifyError(redactSecrets(text).text).category, want, text);
  }
});

/* ----------------------- instance-name safety --------------------- */

Deno.test("instance name: a collective-scoped target is storable", () => {
  // The bug this exists to prevent: swamp rejects '/' in a data name, and a
  // bundled workflow's name is REQUIRED to be collective-scoped -- so the
  // targets most worth investigating were the ones that could not be written.
  const n = sanitizeInstanceName("@sntxrr/unifi-drift-watch");
  assertEquals(n, "@sntxrr%2Funifi-drift-watch");
  assertEquals(/[/\\]/.test(n), false);
});

Deno.test("instance name: an unscoped target is left alone", () => {
  assertEquals(sanitizeInstanceName("nightly-backup"), "nightly-backup");
  assertEquals(sanitizeInstanceName("home-udm"), "home-udm");
});

Deno.test("instance name: path traversal is defused", () => {
  const n = sanitizeInstanceName("../../etc/passwd");
  assertEquals(n.includes(".."), false);
  assertEquals(n.includes("/"), false);
});

Deno.test("instance name: backslashes and whitespace are encoded", () => {
  assertEquals(sanitizeInstanceName("a\\b c"), "a%5Cb%20c");
});

Deno.test("instance name: distinct targets cannot collide", () => {
  // Encoding rather than folding is what keeps these apart -- mapping '/' to
  // '-' would interleave two unrelated targets' histories under one instance.
  assertEquals(sanitizeInstanceName("@acme/thing"), "@acme%2Fthing");
  assertEquals(sanitizeInstanceName("@acme-thing"), "@acme-thing");
  // And a name that already contains a percent cannot forge an encoding.
  assertEquals(
    sanitizeInstanceName("a%2Fb") === sanitizeInstanceName("a/b"),
    false,
  );
});

Deno.test("instance name: a target cannot overwrite a stable handle", () => {
  // Reproduced before this rule: `investigate target=recent` replaced the
  // list at data.latest('triage', 'recent') with a single finding.
  assertEquals(sanitizeInstanceName("recent"), "%72ecent");
  assertEquals(sanitizeInstanceName("current"), "%63urrent");
  // Only the exact names are reserved.
  assertEquals(sanitizeInstanceName("recent-sync"), "recent-sync");
  // And a name that spells the encoding cannot forge it.
  assertEquals(
    sanitizeInstanceName("%72ecent") === sanitizeInstanceName("recent"),
    false,
  );
});

Deno.test("instance name: never returns empty", () => {
  assertEquals(sanitizeInstanceName("///"), "%2F%2F%2F");
  assertEquals(sanitizeInstanceName("   "), "unnamed");
  assertEquals(sanitizeInstanceName(""), "unnamed");
});

/* ------------------------- recent failures ------------------------ */

const NOW = Date.parse("2026-08-04T18:00:00Z");

const head = (
  target: string,
  kind: string,
  createdAt: string,
  body: Record<string, unknown>,
  type = kind === "workflow" ? "workflow" : "@acme/thing",
): SummaryHead => ({ target, kind, type, createdAt, body });

Deno.test("recent: lists only targets whose latest run failed, newest first", () => {
  const sel = selectRecentFailures(
    [
      head("green", "model", "2026-08-04T17:59:00Z", { status: "succeeded" }),
      head("older", "model", "2026-08-04T10:00:00Z", {
        status: "failed",
        error: "connect ECONNREFUSED 192.0.2.1:443",
      }),
      head("newer", "model", "2026-08-04T17:00:00Z", {
        status: "failed",
        error: "401 Unauthorized",
      }),
    ],
    NOW,
    24,
    "auto",
    20,
  );
  assertEquals(sel.failures.map((f) => f.target), ["newer", "older"]);
  assertEquals(sel.failures.map((f) => f.category), ["auth", "unreachable"]);
});

Deno.test("recent: a failure older than the window is counted, not dropped", () => {
  // A weekly job broken for days is still broken. A narrow window must not
  // make it read as healthy -- the caller is told how many to widen for.
  const sel = selectRecentFailures(
    [head("weekly", "workflow", "2026-07-30T00:00:00Z", { status: "failed" })],
    NOW,
    24,
    "auto",
    20,
  );
  assertEquals(sel.failures.length, 0);
  assertEquals(sel.staleFailing, 1);
  assertEquals(buildRecentSummary(sel, 24).includes("1 other target"), true);
});

Deno.test("recent: any non-success status is a failure", () => {
  const sel = selectRecentFailures(
    [head("x", "workflow", "2026-08-04T17:00:00Z", { status: "cancelled" })],
    NOW,
    24,
    "auto",
    20,
  );
  assertEquals(sel.failures[0]?.status, "cancelled");
});

Deno.test("recent: an undated failure is listed, and sorts last", () => {
  // Missing a failure is the worse mistake than listing one we cannot date.
  const sel = selectRecentFailures(
    [
      head("undated", "model", "unknown", { status: "failed" }),
      head("dated", "model", "2026-08-04T17:00:00Z", { status: "failed" }),
    ],
    NOW,
    1,
    "auto",
    20,
  );
  assertEquals(sel.failures.map((f) => f.target), ["dated", "undated"]);
});

Deno.test("recent: limit truncates the list but counts the rest", () => {
  const heads = [1, 2, 3].map((i) =>
    head(`t${i}`, "model", `2026-08-04T1${i}:00:00Z`, { status: "failed" })
  );
  const sel = selectRecentFailures(heads, NOW, 24, "auto", 2);
  assertEquals(sel.failures.map((f) => f.target), ["t3", "t2"]);
  assertEquals(sel.omitted, 1);
  assertEquals(buildRecentSummary(sel, 24).startsWith("3 target(s)"), true);
});

Deno.test("recent: kind filters the list but not the root-cause lookup", () => {
  const sel = selectRecentFailures(
    [
      head("nightly", "workflow", "2026-08-04T17:00:00Z", {
        status: "failed",
        failures: [{ modelName: "home-udm", methodName: "drift" }],
      }),
      head("home-udm", "model", "2026-08-04T16:59:00Z", {
        status: "failed",
        methodName: "drift",
        error: "UniFi login to 192.0.2.1 failed (403)",
      }),
    ],
    NOW,
    24,
    "workflow",
    20,
  );
  assertEquals(sel.failures.length, 1);
  assertEquals(sel.failures[0].failingMethod, "home-udm → drift");
  assertEquals(sel.failures[0].rootCauseModel, "home-udm");
  assertEquals(sel.failures[0].category, "auth");
});

Deno.test("recent: a workflow whose step model left no error still names the step", () => {
  // An assert or expression step records no model error. The step name is
  // still the most useful thing to report -- and the run did fail, so the
  // category is `unrecorded`, never `none`.
  const f = describeFailure(
    head("nightly", "workflow", "2026-08-04T17:00:00Z", {
      status: "failed",
      failures: [{ modelName: "gate", methodName: "check" }],
    }),
    new Map(),
  );
  assertEquals(f.failingMethod, "gate → check");
  assertEquals(f.rootCauseModel, null);
  assertEquals(f.category, "unrecorded");
});

Deno.test("recent: a step model whose latest run succeeded does not read as none", () => {
  // The hop reads the step model's LATEST summary. When that model has run
  // successfully since, it carries no error -- and the workflow still failed.
  const f = describeFailure(
    head("notify-chain", "workflow", "2026-08-04T17:00:00Z", {
      status: "failed",
      failures: [{ modelName: "apprise", methodName: "notify" }],
    }),
    new Map([["apprise", { status: "succeeded" }]]),
  );
  assertEquals(f.status, "failed");
  assertEquals(f.failingMethod, "apprise → notify");
  assertEquals(f.rootCauseModel, null);
  assertEquals(f.category, "unrecorded");
  assertEquals(f.error, null);
});

Deno.test("recent: a failed model summary with no error is unrecorded", () => {
  const f = describeFailure(
    head("x", "model", "2026-08-04T17:00:00Z", { status: "failed" }),
    new Map(),
  );
  assertEquals(f.category, "unrecorded");
});

Deno.test("recent: errors are redacted after classification", () => {
  const f = describeFailure(
    head("x", "model", "2026-08-04T17:00:00Z", {
      status: "failed",
      error: "403 Forbidden: token=abc123",
    }),
    new Map(),
  );
  assertEquals(f.category, "auth");
  assertEquals(f.error?.includes("abc123"), false);
  assertEquals(f.redactions, 1);
});

Deno.test("recent: nothing failing says so plainly", () => {
  const sel = selectRecentFailures([], NOW, 24, "auto", 20);
  assertEquals(
    buildRecentSummary(sel, 24),
    "Nothing has failed in the last 24h.",
  );
});

/** A fake data repository keyed by `${type}|${id}|${name}|${version}`. */
function fakeContext(
  records: {
    name: string;
    version: number;
    modelId: string;
    modelType: string;
    tags?: Record<string, string>;
    createdAt?: string;
    content?: string;
  }[],
) {
  const key = (t: string, i: string, n: string, v?: number) =>
    `${t}|${i}|${n}|${v}`;
  const byKey = new Map(
    records.map((r) => [key(r.modelType, r.modelId, r.name, r.version), r]),
  );
  const predicates: string[] = [];
  return {
    predicates,
    context: {
      queryData: (predicate: string) => {
        predicates.push(predicate);
        return Promise.resolve(records);
      },
      dataRepository: {
        findByName: (t: string, i: string, n: string, v?: number) => {
          const r = byKey.get(key(t, i, n, v));
          return Promise.resolve(
            r?.createdAt
              ? { version: r.version, createdAt: r.createdAt }
              : null,
          );
        },
        getContent: (t: string, i: string, n: string, v?: number) => {
          const r = byKey.get(key(t, i, n, v));
          return Promise.resolve(
            r?.content === undefined
              ? null
              : new TextEncoder().encode(r.content),
          );
        },
      },
    },
  };
}

Deno.test("recent: reads every summary by exact version and names it by tag", async () => {
  const { context, predicates } = fakeContext([
    {
      name: WORKFLOW_SUMMARY,
      version: 7,
      modelId: "w-1",
      modelType: "workflow",
      tags: { modelName: "@acme/nightly" },
      createdAt: "2026-08-04T17:00:00Z",
      content: '{"status":"failed"}',
    },
    {
      name: METHOD_SUMMARY,
      version: 3,
      modelId: "m-1",
      modelType: "@acme/thing",
      createdAt: "2026-08-04T16:00:00Z",
      content: '{"status":"succeeded"}',
    },
  ]);
  const { heads, skipped } = await readSummaryHeads(context);
  assertEquals(skipped, 0);
  assertEquals(predicates.length, 1);
  assertEquals(heads.map((h) => [h.target, h.kind]), [
    ["@acme/nightly", "workflow"],
    // No modelName tag: fall back to the id rather than dropping the target.
    ["m-1", "model"],
  ]);
  assertEquals(heads[0].createdAt, "2026-08-04T17:00:00.000Z");
  // The repository type key travels with the head: "workflow", or the model type.
  assertEquals(heads.map((h) => h.type), ["workflow", "@acme/thing"]);
});

Deno.test("recent: an unreadable or corrupt summary is skipped, not fatal", async () => {
  const { context } = fakeContext([
    {
      name: METHOD_SUMMARY,
      version: 1,
      modelId: "gone",
      modelType: "@acme/thing",
    },
    {
      name: METHOD_SUMMARY,
      version: 1,
      modelId: "corrupt",
      modelType: "@acme/thing",
      createdAt: "2026-08-04T16:00:00Z",
      content: "{not json",
    },
    {
      name: METHOD_SUMMARY,
      version: 2,
      modelId: "ok",
      modelType: "@acme/thing",
      tags: { modelName: "widget" },
      createdAt: "2026-08-04T16:00:00Z",
      content: '{"status":"failed"}',
    },
  ]);
  const { heads, skipped } = await readSummaryHeads(context);
  assertEquals(skipped, 2);
  assertEquals(heads.map((h) => h.target), ["widget"]);
});

Deno.test("recent: a runtime without queryData fails loudly", async () => {
  const { context } = fakeContext([]);
  let message = "";
  try {
    await readSummaryHeads({ ...context, queryData: undefined });
  } catch (err) {
    message = (err as Error).message;
  }
  assertEquals(message.includes("queryData"), true);
});

Deno.test("recent: each failure carries its model type", () => {
  // The case this exists for: a run-history line names only a type, and the
  // type has several instances. Only the failing one should come back, and it
  // must be recognisable as an instance of that type without a catalog search.
  const sel = selectRecentFailures(
    [
      head("docker-ssh", "model", "2026-08-04T17:00:00Z", {
        status: "failed",
        methodName: "exec",
        error: "connect ECONNREFUSED 192.0.2.7:22",
      }, "@acme/ssh/host"),
      head("sinner-ssh", "model", "2026-08-04T16:00:00Z", {
        status: "succeeded",
      }, "@acme/ssh/host"),
      head("nightly", "workflow", "2026-08-04T15:00:00Z", { status: "failed" }),
    ],
    NOW,
    24,
    "auto",
    20,
  );
  assertEquals(
    sel.failures.map((f) => [f.target, f.targetType]),
    [["docker-ssh", "@acme/ssh/host"], ["nightly", "workflow"]],
  );
  const text = buildRecentSummary(sel, 24);
  assertEquals(text.includes("docker-ssh (model @acme/ssh/host)"), true);
  assertEquals(text.includes("nightly (workflow)"), true);
});

/** One target's summary history, newest version last, as stored records. */
function history(
  modelId: string,
  target: string,
  runs: [createdAt: string, status: string, error?: string][],
  modelType = "@acme/ssh/host",
) {
  return runs.map(([createdAt, status, error], i) => ({
    name: METHOD_SUMMARY,
    version: i + 1,
    modelId,
    modelType,
    tags: { modelName: target },
    createdAt,
    content: JSON.stringify({ status, methodName: "exec", error }),
  }));
}

/** Only each target's latest version, as `queryData` returns them. */
const latestOnly = <T extends { modelId: string; version: number }>(
  records: T[],
) =>
  records.filter((r) =>
    !records.some((o) => o.modelId === r.modelId && o.version > r.version)
  );

async function recentOf(
  records: ReturnType<typeof history>,
  withinHours: number,
  maxVersions = 60,
  limit = 20,
) {
  const { context } = fakeContext(records);
  const heads = (await readSummaryHeads({
    ...context,
    queryData: () => Promise.resolve(latestOnly(records)),
  })).heads;
  const { recovered, truncated } = await readRecoveredFailures(
    context,
    heads,
    NOW,
    withinHours,
    "auto",
    maxVersions,
  );
  return {
    sel: selectRecentFailures(
      heads,
      NOW,
      withinHours,
      "auto",
      limit,
      recovered,
    ),
    truncated,
  };
}

Deno.test("recent: a target that failed in the window and recovered is listed", async () => {
  // The daily-summary case: run history names a type whose failing instance
  // has already succeeded again. A head-only read listed nothing, so the
  // instance could not be named.
  const { sel } = await recentOf(
    history("m-1", "edge-ssh", [
      ["2026-08-04T09:00:00Z", "succeeded"],
      ["2026-08-04T10:00:00Z", "failed", "connect ECONNREFUSED 192.0.2.7:22"],
      ["2026-08-04T11:00:00Z", "failed", "connect ECONNREFUSED 192.0.2.7:22"],
      ["2026-08-04T12:00:00Z", "succeeded"],
      ["2026-08-04T13:00:00Z", "succeeded"],
    ]),
    24,
  );
  assertEquals(sel.failures.length, 1);
  const f = sel.failures[0];
  assertEquals(f.target, "edge-ssh");
  assertEquals(f.targetType, "@acme/ssh/host");
  assertEquals(f.failing, false);
  assertEquals(f.failedAt, "2026-08-04T11:00:00.000Z");
  // The first success after the newest failure, not the latest success.
  assertEquals(f.recoveredAt, "2026-08-04T12:00:00.000Z");
  assertEquals(f.failureCount, 2);
  assertEquals(f.category, "unreachable");
  assertEquals(
    buildRecentSummary(sel, 24).includes(
      "edge-ssh (model @acme/ssh/host) at `exec` — **unreachable** — " +
        "failed 2x, last at 2026-08-04T11:00:00.000Z, recovered at " +
        "2026-08-04T12:00:00.000Z",
    ),
    true,
  );
});

Deno.test("recent: a failure that recovered before the window is not listed", async () => {
  const { sel, truncated } = await recentOf(
    history("m-1", "edge-ssh", [
      ["2026-08-02T10:00:00Z", "failed"],
      ["2026-08-02T11:00:00Z", "succeeded"],
      ["2026-08-04T12:00:00Z", "succeeded"],
    ]),
    24,
  );
  assertEquals(sel.failures.length, 0);
  assertEquals(truncated, 0);
});

Deno.test("recent: still-failing targets sort ahead of recovered ones", async () => {
  const { sel } = await recentOf(
    [
      // Recovered, with the newest failure of all -- still listed second.
      ...history("m-1", "edge-ssh", [
        ["2026-08-04T17:00:00Z", "failed"],
        ["2026-08-04T17:30:00Z", "succeeded"],
      ]),
      ...history("m-2", "store-ssh", [
        ["2026-08-04T09:00:00Z", "succeeded"],
        ["2026-08-04T10:00:00Z", "failed", "401 Unauthorized"],
      ]),
    ],
    24,
  );
  assertEquals(
    sel.failures.map((f) => [f.target, f.failing]),
    [["store-ssh", true], ["edge-ssh", false]],
  );
  assertEquals(sel.failures[0].recoveredAt, null);
  assertEquals(sel.failures[0].failureCount, null);
  assertEquals(
    buildRecentSummary(sel, 24).includes("still failing listed before"),
    true,
  );
});

Deno.test("recent: limit counts recovered targets, cutting them before failing ones", async () => {
  const { sel } = await recentOf(
    [
      ...history("m-1", "a", [
        ["2026-08-04T10:00:00Z", "failed"],
        ["2026-08-04T11:00:00Z", "succeeded"],
      ]),
      ...history("m-2", "b", [["2026-08-04T09:00:00Z", "failed"]]),
    ],
    24,
    60,
    1,
  );
  assertEquals(sel.failures.map((f) => f.target), ["b"]);
  assertEquals(sel.omitted, 1);
});

Deno.test("recent: a walk that runs out of versions inside the window says so", async () => {
  const runs: [string, string][] = [["2026-08-04T10:00:00Z", "failed"]];
  for (let i = 0; i < 5; i++) {
    runs.push([`2026-08-04T1${i + 1}:00:00Z`, "succeeded"]);
  }
  const all = history("m-1", "busy", runs);
  // Two versions back reaches neither the failure nor the window start.
  const short = await recentOf(all, 24, 2);
  assertEquals(short.sel.failures.length, 0);
  assertEquals(short.truncated, 1);
  const full = await recentOf(all, 24, 60);
  assertEquals(full.sel.failures.map((f) => f.target), ["busy"]);
  assertEquals(full.truncated, 0);
});

Deno.test("recent: a walk that leaves the window before maxVersions is not truncated", async () => {
  // Older versions exist beyond the cap, but the walk has already passed the
  // window start -- nothing in the window went unread.
  const { sel, truncated } = await recentOf(
    history("m-1", "busy", [
      ["2026-08-01T10:00:00Z", "failed"],
      ["2026-08-01T11:00:00Z", "succeeded"],
      ["2026-08-01T12:00:00Z", "succeeded"],
      ["2026-08-04T10:00:00Z", "succeeded"],
      ["2026-08-04T11:00:00Z", "succeeded"],
    ]),
    24,
    2,
  );
  assertEquals(sel.failures.length, 0);
  assertEquals(truncated, 0);
});

Deno.test("recent: the recorded resource matches its schema, recovered entries included", async () => {
  const now = Date.now();
  const at = (hoursAgo: number) =>
    new Date(now - hoursAgo * 3_600_000).toISOString();
  const records = [
    ...history("m-1", "edge-ssh", [
      [at(3), "failed", "401 Unauthorized"],
      [at(2), "succeeded"],
    ]),
    ...history("m-2", "store-ssh", [[at(1), "failed"]]),
  ];
  const { context } = fakeContext(records);
  const written: unknown[] = [];
  await model.methods.recent.execute(
    { withinHours: 24, kind: "auto", limit: 20, maxVersions: 60 },
    {
      ...context,
      queryData: () => Promise.resolve(latestOnly(records)),
      repoDir: ".",
      globalArgs: {},
      writeResource: (_s: string, _i: string, data: unknown) => {
        written.push(data);
        return Promise.resolve({});
      },
      logger: { info: () => {}, warning: () => {} },
    },
  );
  const rec = model.resources.recent.schema.parse(written[0]);
  assertEquals(
    rec.failures.map((f) => [f.target, f.failing, f.failureCount]),
    [["store-ssh", true, null], ["edge-ssh", false, 1]],
  );
  assertEquals(rec.historyTruncated, 0);
});

/* --------------------------- investigate --------------------------- */

Deno.test("investigate: a failed workflow that recorded no step error, whose step model has since succeeded, is unrecorded", async () => {
  // The fallback hop, made only when the workflow run recorded no error for
  // its failed step: it reads the step model's latest summary, which carries
  // no error once that model has succeeded again. The finding must still say
  // the workflow is failing.
  const dir = await Deno.makeTempDir();
  try {
    await Deno.mkdir(`${dir}/models`, { recursive: true });
    await Deno.mkdir(`${dir}/workflows`, { recursive: true });
    await Deno.writeTextFile(
      `${dir}/models/apprise.yaml`,
      "type: '@acme/apprise'\nid: m-1\nname: apprise\n",
    );
    await Deno.writeTextFile(
      `${dir}/workflows/notify-chain.yaml`,
      "id: w-1\nname: notify-chain\n",
    );
    const bodies: Record<string, Record<number, Record<string, unknown>>> = {
      "workflow/w-1": {
        1: {
          status: "failed",
          failures: [{ modelName: "apprise", methodName: "notify" }],
        },
      },
      "@acme/apprise/m-1": { 1: { status: "succeeded", methodName: "notify" } },
    };
    const latestOf = (k: string) =>
      Math.max(...Object.keys(bodies[k]).map(Number));
    const written: {
      spec: string;
      instance: string;
      data: Record<string, unknown>;
    }[] = [];
    const enc = new TextEncoder();
    const context = {
      repoDir: dir,
      globalArgs: {},
      writeResource: (spec: string, instance: string, data: unknown) => {
        written.push({ spec, instance, data: data as Record<string, unknown> });
        return Promise.resolve({ spec, instance });
      },
      dataRepository: {
        findByName: (type: string, id: string, _n: string, v?: number) => {
          const k = `${type}/${id}`;
          if (!bodies[k]) return Promise.resolve(null);
          const version = v ?? latestOf(k);
          return Promise.resolve(
            bodies[k][version]
              ? { version, createdAt: "2026-08-04T17:00:00Z" }
              : null,
          );
        },
        getContent: (type: string, id: string, _n: string, v?: number) => {
          const k = `${type}/${id}`;
          const b = bodies[k]?.[v ?? (bodies[k] ? latestOf(k) : 0)];
          return Promise.resolve(b ? enc.encode(JSON.stringify(b)) : null);
        },
      },
      logger: { info: () => {}, warning: () => {} },
    };
    await model.methods.investigate.execute(
      { target: "notify-chain", kind: "auto", maxVersions: 60 },
      context,
    );
    const finding = written.find((w) => w.instance === "current")!.data;
    assertEquals(finding.failing, true);
    assertEquals(finding.failingMethod, "apprise → notify");
    assertEquals(finding.category, "unrecorded");
    assertEquals(
      String(finding.summary).includes("Nothing to investigate"),
      false,
    );
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

/* ------------------ caller errors and never-run ------------------- */

Deno.test("classify: a rejected call argument is caller_args, not config", () => {
  // Swamp's wording when a call's arguments fail the method schema. The
  // definition holds no method arguments, so "go to the YAML" is wrong here.
  const c = classifyError(
    "Method arguments validation failed: Too big: expected number to be " +
      '<=720 at "withinHours"',
  );
  assertEquals(c.category, "caller_args");
  assertEquals(c.matched, true);
});

Deno.test("classify: other validation failures stay config", () => {
  assertEquals(classifyError("schema validation failed").category, "config");
});

Deno.test("nested scalars: reads a mapping's children and stops at the next key", () => {
  const text = [
    "id: w-1",
    "name: archive-nightly-dump",
    "description: >-",
    "  schedule: not-this-one",
    "tags:",
    "  runs-on: scheduler-a",
    "  kind: backup",
    "  nested:",
    "    deep: ignored",
    "trigger:",
    "  # monthly",
    '  schedule: "0 8 3 * *"',
    "jobs:",
    "  schedule: not-a-trigger",
  ].join("\n");
  assertEquals(readNestedScalars(text, "trigger"), { schedule: "0 8 3 * *" });
  assertEquals(readNestedScalars(text, "tags"), {
    "runs-on": "scheduler-a",
    kind: "backup",
  });
  assertEquals(readNestedScalars(text, "absent"), {});
});

Deno.test("rank names: a near-miss guess puts the intended name first", () => {
  const near = rankNames("nightly-dump", [
    { name: "archive-nightly-dump", kind: "workflow" },
    { name: "archive-photos", kind: "workflow" },
    { name: "widget", kind: "model" },
  ]);
  assertEquals(near[0].name, "archive-nightly-dump");
  // A candidate sharing no word with the guess is never suggested.
  assertEquals(near.some((n) => n.name === "widget"), false);
});

Deno.test("rank names: nothing in common suggests nothing", () => {
  assertEquals(rankNames("zzz", [{ name: "widget", kind: "model" }]), []);
});

Deno.test("placement: parses key=value, refuses anything else", () => {
  assertEquals(parsePlacement("runs-on=scheduler-a"), {
    key: "runs-on",
    value: "scheduler-a",
  });
  assertEquals(parsePlacement(undefined), null);
  assertEquals(parsePlacement("  "), null);
  let message = "";
  try {
    parsePlacement("scheduler-a");
  } catch (err) {
    message = (err as Error).message;
  }
  assertEquals(message.includes("key=value"), true);
  assertEquals(
    placedHere({ "runs-on": "a" }, { key: "runs-on", value: "a" }),
    true,
  );
  assertEquals(
    placedHere({ "runs-on": "b" }, { key: "runs-on", value: "a" }),
    false,
  );
  assertEquals(placedHere({}, null), true);
});

Deno.test("recent: the investigator's own failures are flagged and listed last", () => {
  const sel = selectRecentFailures(
    [
      head("triage", "model", "2026-08-04T17:30:00Z", {
        status: "failed",
        methodName: "investigate",
        error: 'No model named "nightly" found.',
      }, MODEL_TYPE),
      head("widget", "model", "2026-08-04T17:00:00Z", {
        status: "failed",
        error: "401 Unauthorized",
      }),
    ],
    NOW,
    24,
    "auto",
    20,
    [],
    { selfType: MODEL_TYPE },
  );
  assertEquals(sel.failures.map((f) => [f.target, f.selfInflicted]), [
    ["widget", false],
    ["triage", true],
  ]);
  const text = buildRecentSummary(sel, 24);
  assertEquals(text.includes("1 target(s) failed"), true);
  assertEquals(text.includes("investigator's own runs (investigate)"), true);
});

Deno.test("recent: only the investigator failing reads as nothing in the fleet", () => {
  const sel = selectRecentFailures(
    [head("triage", "model", "2026-08-04T17:30:00Z", {
      status: "failed",
      methodName: "recent",
      error: "Method arguments validation failed: Too big",
    }, MODEL_TYPE)],
    NOW,
    24,
    "auto",
    20,
    [],
    { selfType: MODEL_TYPE },
  );
  const text = buildRecentSummary(sel, 24);
  assertEquals(text.includes("Nothing in the fleet failed"), true);
  assertEquals(text.includes("Run `investigate`"), false);
});

Deno.test("recent: each failure reports its definition path", () => {
  const sel = selectRecentFailures(
    [head("widget", "model", "2026-08-04T17:00:00Z", { status: "failed" })],
    NOW,
    24,
    "auto",
    20,
    [],
    {
      definitions: [{
        name: "widget",
        kind: "model",
        type: "@acme/thing",
        id: "m-1",
        definitionPath: "models/@acme/thing/m-1.yaml",
        schedule: null,
        tags: {},
      }],
    },
  );
  assertEquals(sel.failures[0].definitionPath, "models/@acme/thing/m-1.yaml");
});

Deno.test("recent: a success of the same method seconds later is a quick retry", async () => {
  // The caller passed a bad value, saw the error, and retried with a good
  // one. That is not the remote recovering, and must not read like it.
  const { sel } = await recentOf(
    history("m-1", "backup-a", [
      ["2026-08-04T10:00:00Z", "succeeded"],
      ["2026-08-04T17:00:00Z", "failed", "path a/file: not a directory"],
      ["2026-08-04T17:00:17Z", "succeeded"],
    ]),
    24,
  );
  assertEquals(sel.failures[0].quickRetry, true);
  assertEquals(
    buildRecentSummary(sel, 24).includes("a caller correcting its own input"),
    true,
  );
});

Deno.test("recent: a recovery hours later is not a quick retry", async () => {
  const { sel } = await recentOf(
    history("m-1", "backup-a", [
      ["2026-08-04T10:00:00Z", "failed", "connect ECONNREFUSED 192.0.2.1:22"],
      ["2026-08-04T12:00:00Z", "succeeded"],
    ]),
    24,
  );
  assertEquals(sel.failures[0].quickRetry, false);
});

Deno.test("quick retry: a different method succeeding does not count", () => {
  assertEquals(
    isQuickRetry({
      failed: head("m", "model", "2026-08-04T17:00:00Z", {
        status: "failed",
        methodName: "restore",
      }),
      recoveredAt: "2026-08-04T17:00:10Z",
      recoveredMethod: "check",
      failureCount: 1,
    }),
    false,
  );
});

Deno.test("recent: a scheduled workflow that never ran here is listed", async () => {
  const dir = await fixtureRepo({
    "workflows/a.yaml": "id: w-a\nname: archive-monthly\ntags:\n" +
      "  runs-on: scheduler-a\ntrigger:\n  schedule: '0 8 3 * *'\n",
    "workflows/b.yaml": "id: w-b\nname: archive-daily\ntags:\n" +
      "  runs-on: scheduler-a\ntrigger:\n  schedule: '0 1 * * *'\n",
    "workflows/c.yaml": "id: w-c\nname: elsewhere-job\ntags:\n" +
      "  runs-on: scheduler-b\ntrigger:\n  schedule: '0 2 * * *'\n",
    "workflows/d.yaml": "id: w-d\nname: by-hand\n",
  });
  try {
    const definitions = await listDefinitions(dir, "auto");
    const heads = [
      head("archive-daily", "workflow", "2026-08-04T01:00:00Z", {
        status: "succeeded",
      }),
    ];
    const here = selectRecentFailures(heads, NOW, 24, "auto", 20, [], {
      definitions,
      placement: parsePlacement("runs-on=scheduler-a"),
    });
    assertEquals(here.scheduledNeverRun.map((n) => n.target), [
      "archive-monthly",
    ]);
    assertEquals(here.scheduledNeverRun[0].schedule, "0 8 3 * *");
    // No placement: every scheduled workflow is meant to run here.
    const any = selectRecentFailures(heads, NOW, 24, "auto", 20, [], {
      definitions,
    });
    assertEquals(any.scheduledNeverRun.map((n) => n.target), [
      "archive-monthly",
      "elsewhere-job",
    ]);
    assertEquals(
      buildRecentSummary(here, 24).includes("archive-monthly (`0 8 3 * *`)"),
      true,
    );
    // kind=model asks about models only.
    assertEquals(
      selectRecentFailures(heads, NOW, 24, "model", 20, [], { definitions })
        .scheduledNeverRun.length,
      0,
    );
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("recent: the summary says when the window was capped", () => {
  const sel = selectRecentFailures([], NOW, MAX_WINDOW_HOURS, "auto", 20);
  assertEquals(
    buildRecentSummary(sel, MAX_WINDOW_HOURS, 744).startsWith(
      `Asked for 744h; the window is capped at ${MAX_WINDOW_HOURS}h.`,
    ),
    true,
  );
});

/** A minimal method context over in-memory summary bodies. */
function methodContext(
  dir: string,
  bodies: Record<string, Record<number, Record<string, unknown>>>,
  records: {
    name: string;
    version: number;
    modelId: string;
    modelType: string;
    tags?: Record<string, string>;
  }[] = [],
) {
  const latestOf = (k: string) =>
    Math.max(...Object.keys(bodies[k]).map(Number));
  const written: {
    spec: string;
    instance: string;
    data: Record<string, unknown>;
  }[] = [];
  const warnings: string[] = [];
  const enc = new TextEncoder();
  return {
    written,
    warnings,
    context: {
      repoDir: dir,
      globalArgs: {},
      writeResource: (spec: string, instance: string, data: unknown) => {
        written.push({ spec, instance, data: data as Record<string, unknown> });
        return Promise.resolve({ spec, instance });
      },
      queryData: () => Promise.resolve(records),
      dataRepository: {
        findByName: (type: string, id: string, _n: string, v?: number) => {
          const k = `${type}/${id}`;
          if (!bodies[k]) return Promise.resolve(null);
          const version = v ?? latestOf(k);
          return Promise.resolve(
            bodies[k][version]
              ? { version, createdAt: "2026-08-04T17:00:00Z" }
              : null,
          );
        },
        getContent: (type: string, id: string, _n: string, v?: number) => {
          const k = `${type}/${id}`;
          const b = bodies[k]?.[v ?? (bodies[k] ? latestOf(k) : 0)];
          return Promise.resolve(b ? enc.encode(JSON.stringify(b)) : null);
        },
      },
      logger: {
        info: () => {},
        warning: (msg: string) => {
          warnings.push(msg);
        },
      },
    },
  };
}

const MONTHLY =
  "id: w-1\nname: archive-nightly-dump\ntags:\n  runs-on: scheduler-a\n" +
  "trigger:\n  schedule: '0 8 3 * *'\n";

Deno.test("investigate: a scheduled workflow with no runs is a failing never-run finding", async () => {
  // It used to throw, which recorded the investigation itself as a failure
  // and read as "nothing to investigate" -- the opposite of the truth.
  const dir = await fixtureRepo({ "workflows/w.yaml": MONTHLY });
  try {
    const { context, written } = methodContext(dir, {});
    await model.methods.investigate.execute(
      { target: "archive-nightly-dump", kind: "workflow", maxVersions: 60 },
      context,
    );
    const finding = written.find((w) => w.instance === "current")!.data;
    assertEquals(finding.currentStatus, "never-run");
    assertEquals(finding.category, "never_run");
    assertEquals(finding.failing, true);
    assertEquals(finding.schedule, "0 8 3 * *");
    assertEquals(String(finding.summary).includes("**failing**"), true);
    assertEquals(
      written.map((w) => w.instance).sort(),
      ["archive-nightly-dump", "current"],
    );
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("investigate: never-run placed on another scheduler is not failing here", async () => {
  const dir = await fixtureRepo({ "workflows/w.yaml": MONTHLY });
  try {
    const { context, written } = methodContext(dir, {});
    await model.methods.investigate.execute(
      {
        target: "archive-nightly-dump",
        kind: "workflow",
        maxVersions: 60,
        placementTag: "runs-on=scheduler-b",
      },
      context,
    );
    const finding = written.find((w) => w.instance === "current")!.data;
    assertEquals(finding.failing, false);
    assertEquals(
      String(finding.meaning).includes("placed on runs-on=scheduler-a"),
      true,
    );
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("investigate: an unknown name suggests the closest real ones", async () => {
  const dir = await fixtureRepo({
    "workflows/w.yaml": MONTHLY,
    "models/@acme/thing/m.yaml": "type: '@acme/thing'\nid: m-1\nname: widget\n",
  });
  try {
    const { context } = methodContext(dir, {});
    let message = "";
    try {
      await model.methods.investigate.execute(
        { target: "nightly-dump", kind: "auto", maxVersions: 60 },
        context,
      );
    } catch (err) {
      message = (err as Error).message;
    }
    assertEquals(
      message.includes("Closest names: archive-nightly-dump (workflow)"),
      true,
    );
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("investigate: an input error says which arguments came from the caller", async () => {
  const dir = await fixtureRepo({
    "models/@acme/thing/m.yaml": "type: '@acme/thing'\nid: m-1\nname: widget\n",
  });
  try {
    const { context, written } = methodContext(dir, {
      "@acme/thing/m-1": {
        1: {
          status: "failed",
          methodName: "restore",
          error: "Method arguments validation failed: path is required",
          methodArgs: ["path", "target"],
          globalArgs: ["repository"],
        },
      },
    });
    await model.methods.investigate.execute(
      { target: "widget", kind: "model", maxVersions: 60 },
      context,
    );
    const finding = written.find((w) => w.instance === "current")!.data;
    assertEquals(finding.category, "caller_args");
    assertEquals(finding.callArgs, ["path", "target"]);
    assertEquals(finding.definitionArgs, ["repository"]);
    assertEquals(
      String(finding.summary).includes(
        "Arguments passed by the caller on each run: path, target. Set in " +
          "the definition (models/@acme/thing/m.yaml): repository.",
      ),
      true,
    );
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("recent: an over-wide window is capped with a warning, not refused", async () => {
  const dir = await fixtureRepo({});
  try {
    const { context, written, warnings } = methodContext(dir, {});
    await model.methods.recent.execute(
      { withinHours: 744, kind: "auto", limit: 20, maxVersions: 60 },
      context,
    );
    const rec = written.find((w) => w.instance === "recent")!.data;
    assertEquals(rec.withinHours, MAX_WINDOW_HOURS);
    assertEquals(rec.requestedHours, 744);
    assertEquals(warnings.length, 1);
    // The method's schema accepts it, so the call itself never fails.
    assertEquals(
      model.methods.recent.arguments.safeParse({ withinHours: 744 }).success,
      true,
    );
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("model: MODEL_TYPE is the model's own type", () => {
  assertEquals(model.type, MODEL_TYPE);
});

Deno.test("recent: the investigator breaking for real is not filed as a caller error", () => {
  // Only input mistakes are the caller's. A lock timeout or a crash after an
  // upgrade means triage itself is broken, and must read like any failure.
  const sel = selectRecentFailures(
    [
      head("triage", "model", "2026-08-04T17:30:00Z", {
        status: "failed",
        methodName: "recent",
        error: 'Lock "triage" held by another process: timed out',
      }, MODEL_TYPE),
      head("triage-b", "model", "2026-08-04T17:20:00Z", {
        status: "failed",
        methodName: "recent",
        error: "Method arguments validation failed: Too big",
      }, MODEL_TYPE),
    ],
    NOW,
    24,
    "auto",
    20,
    [],
    { selfType: MODEL_TYPE },
  );
  assertEquals(sel.failures.map((f) => [f.target, f.selfInflicted]), [
    ["triage", false],
    ["triage-b", true],
  ]);
  assertEquals(
    buildRecentSummary(sel, 24).includes("1 target(s) failed"),
    true,
  );
});

Deno.test("caller error: names, arguments and the old no-runs refusal only", () => {
  const e = (error: string) => isCallerError(classified(error));
  assertEquals(e('No model or workflow named "x" found in /repo.'), true);
  assertEquals(e('No summary reports recorded for workflow "x".'), true);
  assertEquals(e("Method arguments validation failed: bad"), true);
  assertEquals(e("TypeError: cannot read properties of undefined"), false);
  assertEquals(e("connect ECONNREFUSED 192.0.2.1:443"), false);
});

const classified = (error: string) => ({
  error,
  category: classifyError(error, true).category,
});

/* ------------------- workflow-recorded step errors ------------------ */

// Swamp's wording when a definition's expression fails to evaluate. The data
// names are fictional.
const AMBIGUOUS =
  'Invalid expression: Ambiguous data.latest() match: specName "usage" ' +
  "resolves to 2 data items (current, usage). Use the specific data name " +
  "instead.";

Deno.test("classify: an expression error is config, whatever it quotes", () => {
  assertEquals(classifyError(AMBIGUOUS, true).category, "config");
  assertEquals(classifyError(AMBIGUOUS, true).matched, true);
  // Quotes "No such key", which alone would read as not_found.
  assertEquals(
    classifyError(
      "Invalid expression: No such key: index out of bounds, index 0 >= " +
        "size undefined",
      true,
    ).category,
    "config",
  );
  // A vault expression that failed to resolve is not an expression error.
  assertEquals(
    classifyError(
      "Failed to resolve vault expression vault.get('v', 'k'): " +
        "authentication failed",
      true,
    ).category,
    "auth",
  );
});

Deno.test("workflow failure: reads the first failed step and its recorded error", () => {
  assertEquals(
    firstWorkflowFailure({
      failures: [
        { modelName: "reclaimer", methodName: "reclaim", errorMessage: "x" },
        { modelName: "notifier", methodName: "notify", errorMessage: "y" },
      ],
    }),
    { stepModel: "reclaimer", stepMethod: "reclaim", errorMessage: "x" },
  );
  assertEquals(
    firstWorkflowFailure({ failures: [{ modelName: "m", errorMessage: " " }] }),
    { stepModel: "m", stepMethod: null, errorMessage: null },
  );
  assertEquals(firstWorkflowFailure({ failures: [] }), null);
  assertEquals(firstWorkflowFailure({ status: "failed" }), null);
  assertEquals(firstWorkflowFailure(null), null);
});

Deno.test("recent: a workflow's recorded step error wins over the step model's later success", () => {
  const f = describeFailure(
    head("disk-sweep", "workflow", "2026-08-04T17:00:00Z", {
      status: "failed",
      failures: [{
        modelName: "sweeper",
        methodName: "reclaim",
        errorMessage: AMBIGUOUS,
      }],
    }),
    new Map([["sweeper", { status: "succeeded" }]]),
  );
  assertEquals(f.failingMethod, "sweeper → reclaim");
  assertEquals(f.category, "config");
  assertEquals(f.error, AMBIGUOUS);
  // Read from the workflow's own record, not chased into the model.
  assertEquals(f.rootCauseModel, null);
});

Deno.test("recent: a recorded step error is preferred to the step model's own error", () => {
  // The step model's latest summary may be a different, later failure.
  const f = describeFailure(
    head("disk-sweep", "workflow", "2026-08-04T17:00:00Z", {
      status: "failed",
      failures: [{
        modelName: "sweeper",
        methodName: "reclaim",
        errorMessage: AMBIGUOUS,
      }],
    }),
    new Map([["sweeper", { status: "failed", error: "connect ECONNREFUSED" }]]),
  );
  assertEquals(f.category, "config");
  assertEquals(f.error, AMBIGUOUS);
});

Deno.test("investigate: a failed workflow reports the expression error its run recorded", async () => {
  const dir = await fixtureRepo({
    "models/@acme/sweeper/m.yaml":
      "type: '@acme/sweeper'\nid: m-1\nname: sweeper\n",
    "workflows/w.yaml": "id: w-1\nname: disk-sweep\n",
  });
  try {
    const { context, written } = methodContext(dir, {
      "workflow/w-1": {
        1: { status: "succeeded" },
        2: {
          status: "failed",
          failures: [
            {
              modelName: "sweeper",
              methodName: "reclaim",
              errorMessage: AMBIGUOUS,
            },
            {
              modelName: "notifier",
              methodName: "notify",
              errorMessage: "fetch failed",
            },
          ],
        },
      },
      // The step model has succeeded since; its summary holds no error.
      "@acme/sweeper/m-1": { 1: { status: "succeeded", methodName: "x" } },
    });
    await model.methods.investigate.execute(
      { target: "disk-sweep", kind: "workflow", maxVersions: 60 },
      context,
    );
    const finding = written.find((w) => w.instance === "current")!.data;
    assertEquals(finding.failing, true);
    assertEquals(finding.category, "config");
    assertEquals(finding.error, AMBIGUOUS);
    assertEquals(finding.failingMethod, "sweeper → reclaim");
    assertEquals(finding.rootCauseModel, null);
    assertEquals(
      String(finding.summary).includes("Ambiguous data.latest()"),
      true,
    );
    // Not the misleading "read from the model that step invoked" note.
    assertEquals(String(finding.summary).includes("step invoked"), false);
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

/* ------------------------------ resolve ------------------------------ */

Deno.test("description: reads inline and block-scalar descriptions", () => {
  assertEquals(readDescription("id: x\ndescription: one line\n"), "one line");
  assertEquals(
    readDescription(
      "id: x\ndescription: >-\n  Copy the reports\n\n  to cold storage.\n" +
        "name: y\n  indented: after\n",
    ),
    "Copy the reports to cold storage.",
  );
  assertEquals(readDescription("id: x\nname: y\n"), "");
});

Deno.test("resolve tokens: lowercase words, alert noise dropped", () => {
  assertEquals(
    resolveTokens("Cold-store disk-reports STALE: run failed"),
    ["cold", "store", "disk", "reports"],
  );
});

/** Definitions shaped as `listDefinitions` returns them. */
const def = (
  name: string,
  kind: string,
  extra: {
    type?: string;
    tags?: Record<string, string>;
    description?: string;
  } = {},
) => ({
  name,
  kind,
  type: extra.type ?? (kind === "workflow" ? "workflow" : "@acme/thing"),
  id: `${kind}-${name}`,
  definitionPath: `${kind}s/${name}.yaml`,
  schedule: null,
  tags: extra.tags ?? {},
  description: extra.description ?? "",
});

const CATALOG = [
  def("archive-disk-reports", "model", { type: "@acme/cloud/archive" }),
  def("archive-disk-reports", "workflow", {
    tags: { "runs-on": "scheduler-a", kind: "backup" },
    description: "Copy the weekly disk reports to cold storage, then verify.",
  }),
  def("cold-storage-freshness", "workflow", {
    description: "Alert when the newest archived object is too old.",
  }),
  def("archive-photos", "model", { type: "@acme/cloud/archive" }),
  def("backlog-groom", "workflow", {
    tags: { "runs-on": "scheduler-b" },
    description: "Groom the backlog: judge, then reorder.",
  }),
  def("backlog-sync", "model", { type: "@acme/tracker" }),
];

Deno.test("resolve: alert words put the intended workflow first", () => {
  const m = resolveText("cold disk-reports stale", CATALOG);
  assertEquals(m[0].name, "archive-disk-reports");
  assertEquals(m[0].kind, "workflow");
  assertEquals(m[0].runsOn, "scheduler-a");
  assertEquals(m[0].matched, ["cold", "disk", "reports"]);
  assertEquals(m[1].name, "archive-disk-reports");
  assertEquals(m[1].kind, "model");
  assertEquals(m[1].runsOn, null);
  assertEquals(m[0].score > m[1].score, true);
});

Deno.test("resolve: a step name that quotes a whole definition name finds it", () => {
  const m = resolveText("backlog-groom-judgement", CATALOG);
  assertEquals(m[0].name, "backlog-groom");
  assertEquals(m[0].kind, "workflow");
  // backlog-sync shares only "backlog", and no whole-name bonus.
  assertEquals(m[0].score > m[1].score, true);
  assertEquals(m[1].name, "backlog-sync");
});

Deno.test("resolve: a word only in the name is not taken from inside a longer word", () => {
  // "sync" must not match an alert saying "async".
  const m = resolveText("async queue", [def("sync", "model")]);
  assertEquals(m, []);
});

Deno.test("resolve: a tie goes to the workflow, and limit caps the list", () => {
  const defs = [def("nightly", "model"), def("nightly", "workflow")];
  assertEquals(resolveText("nightly", defs).map((m) => m.kind), [
    "workflow",
    "model",
  ]);
  assertEquals(resolveText("archive", CATALOG, 2).length, 2);
});

Deno.test("resolve: matching nothing is an empty list, not a guess", () => {
  assertEquals(resolveText("quasar telemetry", CATALOG), []);
  assertEquals(resolveText("failed stale alert", CATALOG), []);
  assertEquals(
    buildResolveSummary("quasar", []).startsWith('Nothing matched "quasar"'),
    true,
  );
});

Deno.test("resolve: the method records a small ranked list and redacts the text", async () => {
  const dir = await fixtureRepo({
    "workflows/a.yaml": "id: w-1\nname: archive-disk-reports\ntags:\n" +
      "  runs-on: scheduler-a\ndescription: >-\n  Copy the weekly disk " +
      "reports to cold storage.\n",
    "models/@acme/cloud/m.yaml": "type: '@acme/cloud/archive'\nid: m-1\n" +
      "name: archive-disk-reports\n",
    "workflows/b.yaml": "id: w-2\nname: unrelated-thing\n",
  });
  try {
    const { context, written } = methodContext(dir, {});
    await model.methods.resolve.execute(
      { text: "cold disk-reports stale token=hunter2", kind: "auto", limit: 5 },
      context,
    );
    assertEquals(written.length, 1);
    assertEquals(written[0].spec, "resolution");
    assertEquals(written[0].instance, "resolve");
    const data = written[0].data;
    const matches = data.matches as { name: string; kind: string }[];
    assertEquals(matches.map((m) => `${m.name}/${m.kind}`), [
      "archive-disk-reports/workflow",
      "archive-disk-reports/model",
    ]);
    assertEquals(String(data.text).includes("hunter2"), false);
    assertEquals(JSON.stringify(data).includes("hunter2"), false);
    assertEquals(data.definitionsExamined, 3);
    // Small enough to hand an agent with no file tool.
    assertEquals(JSON.stringify(data).length < 2048, true);
    assertEquals(
      model.resources.resolution.schema.safeParse(data).success,
      true,
    );
  } finally {
    await Deno.remove(dir, { recursive: true });
  }
});

Deno.test("instance name: a target named resolve cannot overwrite its handle", () => {
  assertEquals(sanitizeInstanceName("resolve") === "resolve", false);
});
