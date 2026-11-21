const test = require("node:test");
const assert = require("node:assert");
const { execFileSync } = require("node:child_process");
const path = require("node:path");
const { lint } = require("../jwt-lint.js");

const NOW = 1767225600; // 2026-01-01T00:00:00Z
const enc = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const make = (h, p, sig = "c2lnbmF0dXJl") => `${enc(h)}.${enc(p)}.${sig}`;

const goodHeader = { alg: "RS256", typ: "at+jwt", kid: "2026-01" };
const goodPayload = {
  iss: "https://login.example.com",
  sub: "u-1042",
  aud: "https://api.example.com",
  client_id: "web-app",
  iat: NOW - 60,
  exp: NOW + 840,
  jti: "a1b2c3",
  scope: "read:pay",
};
const opts = { now: NOW, audience: "https://api.example.com", issuer: "https://login.example.com", algorithms: ["RS256"] };
const ids = (r) => r.findings.map((f) => f.id);

test("a good token passes clean", () => {
  const r = lint(make(goodHeader, goodPayload), opts);
  assert.deepStrictEqual(r.findings, []);
  assert.strictEqual(r.summary.pass, true);
});

test("Bearer prefix and whitespace are ignored", () => {
  const r = lint("  Bearer " + make(goodHeader, goodPayload) + "\n", opts);
  assert.strictEqual(r.summary.pass, true);
});

test("alg none is an error", () => {
  const r = lint(make({ ...goodHeader, alg: "none" }, goodPayload, ""), opts);
  assert.ok(ids(r).includes("alg-none"));
  assert.ok(!ids(r).includes("sig-empty"));
});

test("alg outside the allow list is an error", () => {
  assert.ok(ids(lint(make({ ...goodHeader, alg: "HS256" }, goodPayload), opts)).includes("alg-not-allowed"));
});

test("HS256 warns for access tokens", () => {
  const r = lint(make({ ...goodHeader, alg: "HS256" }, goodPayload), { ...opts, algorithms: null });
  assert.ok(ids(r).includes("alg-symmetric"));
  assert.strictEqual(r.findings.find((f) => f.id === "alg-symmetric").level, "warn");
});

test("stripped signature", () => {
  assert.ok(ids(lint(make(goodHeader, goodPayload, ""), opts)).includes("sig-empty"));
});

test("typ JWT fails the access-token profile but not the jwt profile", () => {
  const t = make({ ...goodHeader, typ: "JWT" }, goodPayload);
  assert.ok(ids(lint(t, opts)).includes("typ"));
  assert.ok(!ids(lint(t, { ...opts, profile: "jwt" })).includes("typ"));
});

test("application/at+jwt is accepted", () => {
  assert.ok(!ids(lint(make({ ...goodHeader, typ: "application/at+jwt" }, goodPayload), opts)).includes("typ"));
});

test("expired, not yet valid, issued in the future", () => {
  assert.ok(ids(lint(make(goodHeader, { ...goodPayload, exp: NOW - 600 }), opts)).includes("expired"));
  assert.ok(ids(lint(make(goodHeader, { ...goodPayload, nbf: NOW + 600 }), opts)).includes("not-yet-valid"));
  assert.ok(ids(lint(make(goodHeader, { ...goodPayload, iat: NOW + 600 }), opts)).includes("iat-future"));
});

test("leeway covers small clock skew", () => {
  const r = lint(make(goodHeader, { ...goodPayload, exp: NOW - 30 }), opts);
  assert.ok(!ids(r).includes("expired"));
});

test("exp in milliseconds", () => {
  assert.ok(ids(lint(make(goodHeader, { ...goodPayload, exp: (NOW + 600) * 1000 }), opts)).includes("exp-millis"));
});

test("long lifetime warns", () => {
  assert.ok(ids(lint(make(goodHeader, { ...goodPayload, exp: NOW + 86400 }), opts)).includes("lifetime-long"));
});

test("wrong audience and issuer", () => {
  assert.ok(ids(lint(make(goodHeader, { ...goodPayload, aud: "https://other.example.com" }), opts)).includes("aud-mismatch"));
  assert.ok(ids(lint(make(goodHeader, { ...goodPayload, iss: "https://login.example.com/" }), opts)).includes("iss-mismatch"));
});

test("aud array containing the expected audience passes", () => {
  const r = lint(make(goodHeader, { ...goodPayload, aud: ["https://x.example.com", "https://api.example.com"] }), opts);
  assert.ok(!ids(r).includes("aud-mismatch"));
});

test("missing RFC 9068 claims", () => {
  const { jti, client_id, ...rest } = goodPayload;
  const r = lint(make(goodHeader, rest), opts);
  assert.ok(ids(r).includes("missing-jti"));
  assert.ok(ids(r).includes("missing-client_id"));
});

test("jku on an untrusted host, over http, and embedded jwk", () => {
  const t1 = make({ ...goodHeader, jku: "https://evil.example.net/keys" }, goodPayload);
  assert.ok(ids(lint(t1, { ...opts, trustedKeyHosts: ["login.example.com"] })).includes("jku-untrusted"));
  assert.ok(ids(lint(t1, opts)).includes("jku-present"));
  assert.ok(ids(lint(make({ ...goodHeader, jku: "http://login.example.com/keys" }, goodPayload), opts)).includes("jku-http"));
  assert.ok(ids(lint(make({ ...goodHeader, jwk: { kty: "RSA" } }, goodPayload), opts)).includes("jwk-embedded"));
});

test("kid that looks like path traversal", () => {
  assert.ok(ids(lint(make({ ...goodHeader, kid: "../../dev/null" }, goodPayload), opts)).includes("kid-injection"));
});

test("scope as an array, and sensitive claims", () => {
  assert.ok(ids(lint(make(goodHeader, { ...goodPayload, scope: ["read"] }), opts)).includes("scope-type"));
  assert.ok(ids(lint(make(goodHeader, { ...goodPayload, password: "x" }), opts)).includes("sensitive-claim"));
});

test("malformed input", () => {
  assert.ok(ids(lint("", opts)).includes("empty"));
  assert.ok(ids(lint("abc.def", opts)).includes("shape"));
  assert.ok(ids(lint("a.b.c.d.e", opts)).includes("jwe"));
  assert.ok(ids(lint("!!!.e30.x", opts)).includes("header-decode"));
});

test("errors sort first", () => {
  const r = lint(make({ alg: "HS256" }, { exp: NOW - 999 }), { now: NOW });
  const levels = r.findings.map((f) => f.level);
  assert.deepStrictEqual(levels, [...levels].sort((a, b) => ["error", "warn", "info"].indexOf(a) - ["error", "warn", "info"].indexOf(b)));
});

test("CLI exits 0 on a clean token and 1 on errors", () => {
  const bin = path.join(__dirname, "..", "jwt-lint.js");
  const out = execFileSync("node", [bin, make(goodHeader, goodPayload), "--now", String(NOW), "--aud", opts.audience, "--iss", opts.issuer]).toString();
  assert.match(out, /0 errors/);
  assert.throws(() => execFileSync("node", [bin, make({ alg: "none" }, goodPayload, ""), "--now", String(NOW)], { stdio: "pipe" }), (e) => e.status === 1);
});

test("CLI reads from stdin", () => {
  const bin = path.join(__dirname, "..", "jwt-lint.js");
  const out = execFileSync("node", [bin, "--json", "--now", String(NOW)], { input: make(goodHeader, goodPayload) }).toString();
  assert.strictEqual(JSON.parse(out).summary.error, 0);
});
