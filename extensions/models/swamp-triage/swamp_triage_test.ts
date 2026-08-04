import { assertEquals } from "jsr:@std/assert@1";
import {
  classifyError,
  readTopLevelScalars,
  redactSecrets,
  reconstructTimeline,
  resolveTargets,
  type RunPoint,
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
  assertEquals(classifyError("401 Unauthorized: token has expired").category, "auth");
});

Deno.test("classify: timeout is distinct from unreachable", () => {
  const c = classifyError("request to https://192.0.2.5 failed: ETIMEDOUT");
  assertEquals(c.category, "timeout");
});

Deno.test("classify: 429 is rate_limit, not auth", () => {
  assertEquals(classifyError("HTTP 429 Too Many Requests").category, "rate_limit");
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

/* ---------------------------- timeline ---------------------------- */

const at = (v: number, iso: string, status: string, error?: string): RunPoint => ({
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
  const d = readTopLevelScalars("type: '@acme/thing'\nid: abc-123\nname: widget\n");
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
  const r = redactSecrets("failed to reach https://admin:s3cr3t@example.com/api");
  assertEquals(r.text, "failed to reach https://admin:[redacted]@example.com/api");
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
