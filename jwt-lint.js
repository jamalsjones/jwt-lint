#!/usr/bin/env node
/*
 * jwt-lint: checks a JWT access token against RFC 7519 (JWT), RFC 8725
 * (JWT best current practices) and RFC 9068 (JWT profile for OAuth 2.0
 * access tokens).
 *
 * One file, no dependencies. It works three ways:
 *   - in a browser, as a plain <script> (it sets window.JwtLint)
 *   - in Node, as a module: const { lint } = require("./jwt-lint.js")
 *   - in Node, as a command: node jwt-lint.js <token> [options]
 *
 * It reads the token. It never verifies the signature: that needs the
 * issuer's key and is your API's job. A token can pass every check here and
 * still be forged, so treat this as a review, not a gate on its own.
 *
 * MIT License. https://github.com/jamalsjones/jwt-lint
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.JwtLint = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  var REF = {
    7519: "RFC 7519",
    8725: "RFC 8725",
    9068: "RFC 9068",
  };

  // Claims RFC 9068 section 2.2 requires in every JWT access token.
  var REQUIRED_AT_CLAIMS = ["iss", "exp", "aud", "sub", "client_id", "iat", "jti"];

  // Payload keys that suggest something private was put in the token.
  // Anyone holding a JWT can read its payload; only the signature is protected.
  var SENSITIVE = /(pass(word)?|secret|ssn|social_?security|credit_?card|card_?number|cvv|private_?key|api_?key)/i;

  var DEFAULTS = {
    profile: "access", // "access" applies RFC 9068; "jwt" checks only RFC 7519/8725 basics
    audience: null, // string or array: what your API expects in aud
    issuer: null, // string: the issuer your API trusts
    algorithms: null, // array: the algorithms your API accepts, e.g. ["RS256", "ES256"]
    trustedKeyHosts: null, // array of hosts allowed in jku / x5u
    leewaySeconds: 60, // clock skew allowed on exp, nbf and iat
    maxLifetimeSeconds: 3600, // warn when exp - iat is longer than this
    now: null, // seconds since epoch; defaults to the current time
  };

  function b64urlDecode(segment) {
    if (!/^[A-Za-z0-9_-]*$/.test(segment)) throw new Error("not base64url");
    var b64 = segment.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    var binary;
    if (typeof atob === "function") binary = atob(b64);
    else binary = Buffer.from(b64, "base64").toString("binary");
    // Decode UTF-8 so names with accents come out right.
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  }

  function parseSegment(segment, name) {
    var text;
    try {
      text = b64urlDecode(segment);
    } catch (e) {
      return { error: "The " + name + " isn't valid base64url." };
    }
    try {
      var value = JSON.parse(text);
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        return { error: "The " + name + " is JSON, but not a JSON object." };
      }
      return { value: value };
    } catch (e) {
      return { error: "The " + name + " doesn't decode to JSON." };
    }
  }

  function hostOf(url) {
    try {
      return new URL(url).host.toLowerCase();
    } catch (e) {
      return null;
    }
  }

  function isNumericDate(v) {
    return typeof v === "number" && isFinite(v);
  }

  function describeSeconds(s) {
    var a = Math.abs(s);
    if (a < 90) return Math.round(a) + " seconds";
    if (a < 5400) return Math.round(a / 60) + " minutes";
    if (a < 172800) return Math.round(a / 3600) + " hours";
    return Math.round(a / 86400) + " days";
  }

  function lint(token, options) {
    var opts = {};
    var k;
    for (k in DEFAULTS) opts[k] = DEFAULTS[k];
    if (options) for (k in options) if (options[k] !== undefined && options[k] !== null && options[k] !== "") opts[k] = options[k];
    if (typeof opts.audience === "string") opts.audience = [opts.audience];
    if (typeof opts.algorithms === "string") opts.algorithms = opts.algorithms.split(/[\s,]+/).filter(Boolean);
    if (typeof opts.trustedKeyHosts === "string") opts.trustedKeyHosts = opts.trustedKeyHosts.split(/[\s,]+/).filter(Boolean);
    var now = opts.now != null ? Number(opts.now) : Math.floor(Date.now() / 1000);
    var leeway = Number(opts.leewaySeconds) || 0;
    var access = opts.profile !== "jwt";

    var findings = [];
    function add(level, id, claim, message, ref) {
      findings.push({ level: level, id: id, claim: claim, message: message, ref: ref || null });
    }

    var raw = String(token || "").trim().replace(/^Bearer\s+/i, "");
    var result = { header: null, payload: null, findings: findings, summary: null };

    if (!raw) {
      add("error", "empty", null, "No token to check.");
      return finish(result);
    }

    var parts = raw.split(".");
    if (parts.length === 5) {
      add("error", "jwe", null, "This has five parts, so it's an encrypted token (JWE). Its claims can't be read without the decryption key, so there's nothing here to lint.", REF[7519] + " §3");
      return finish(result);
    }
    if (parts.length !== 3) {
      add("error", "shape", null, "A signed JWT has three parts separated by dots. This has " + parts.length + ".", REF[7519] + " §7.2");
      return finish(result);
    }

    var h = parseSegment(parts[0], "header");
    var p = parseSegment(parts[1], "payload");
    if (h.error) add("error", "header-decode", null, h.error, REF[7519] + " §7.2");
    if (p.error) add("error", "payload-decode", null, p.error, REF[7519] + " §7.2");
    if (h.error || p.error) return finish(result);

    var header = (result.header = h.value);
    var payload = (result.payload = p.value);
    var signature = parts[2];

    // ---- Header -----------------------------------------------------------

    var alg = header.alg;
    if (typeof alg !== "string" || !alg) {
      add("error", "alg-missing", "alg", "The header has no alg, so there's no stated way to check the signature.", REF[7519] + " §5");
    } else if (alg.toLowerCase() === "none") {
      add("error", "alg-none", "alg", "alg is \"none\": the token isn't signed, so anyone could have written it. Never accept it.", REF[8725] + " §3.1");
    } else {
      if (opts.algorithms && opts.algorithms.length && opts.algorithms.indexOf(alg) === -1) {
        add("error", "alg-not-allowed", "alg", "alg is " + alg + ", which isn't on your allowed list (" + opts.algorithms.join(", ") + "). Check the algorithm against a fixed list, never against what the token says.", REF[8725] + " §3.1");
      }
      if (/^HS/.test(alg)) {
        add(access ? "warn" : "info", "alg-symmetric", "alg", alg + " is a shared-secret algorithm. Every API that can check the token can also mint one. And if your API also accepts RS or ES tokens, an attacker can sign with your public key as the HMAC secret. Prefer RS256 or ES256 for access tokens.", REF[8725] + " §2.1, §3.1");
      }
      if (!/^(HS|RS|PS|ES)(256|384|512)$|^EdDSA$|^Ed25519$|^Ed448$/.test(alg) && alg.toLowerCase() !== "none") {
        add("warn", "alg-unknown", "alg", "alg is " + alg + ", which isn't a JWS signing algorithm most libraries support. Check it's what your issuer meant.", REF[8725] + " §3.1");
      }
    }

    if (signature === "" && typeof alg === "string" && alg.toLowerCase() !== "none") {
      add("error", "sig-empty", null, "alg says " + alg + " but the signature part is empty. The token was stripped of its signature.", REF[8725] + " §3.1");
    }

    if (access) {
      var typ = typeof header.typ === "string" ? header.typ.toLowerCase() : null;
      if (typ !== "at+jwt" && typ !== "application/at+jwt") {
        add("error", "typ", "typ", (header.typ ? "typ is " + header.typ : "There's no typ") + ". RFC 9068 access tokens use at+jwt, and APIs should reject anything else. This stops an ID token or other JWT from passing as an access token.", REF[9068] + " §2.1, §4; " + REF[8725] + " §3.11");
      }
    }

    ["jku", "x5u"].forEach(function (name) {
      if (header[name] === undefined) return;
      var url = header[name];
      var host = hostOf(url);
      if (!host) {
        add("error", name + "-invalid", name, name + " isn't a valid URL.", REF[8725] + " §3.10");
        return;
      }
      if (!/^https:/i.test(url)) {
        add("error", name + "-http", name, name + " points to a key over plain HTTP. Anyone on the network could swap the key.", REF[8725] + " §3.10");
      }
      if (opts.trustedKeyHosts && opts.trustedKeyHosts.length) {
        var ok = opts.trustedKeyHosts.some(function (t) {
          return host === String(t).toLowerCase();
        });
        if (!ok) {
          add("error", name + "-untrusted", name, name + " points to " + host + ", which isn't one of your trusted key hosts. A token that names its own key can bring an attacker's key with it.", REF[8725] + " §3.10");
        }
      } else {
        add("warn", name + "-present", name, name + " tells the API where to fetch the signing key (" + host + "). Fetch keys only from a fixed, trusted location, never from a URL in the token.", REF[8725] + " §3.10");
      }
    });

    if (header.jwk !== undefined) {
      add("error", "jwk-embedded", "jwk", "The header carries its own key (jwk). A token that brings its own key proves nothing unless that key is already trusted.", REF[8725] + " §3.10");
    }
    if (header.x5c !== undefined) {
      add("warn", "x5c-embedded", "x5c", "The header carries a certificate chain (x5c). Only trust it if you validate the chain to a root you already trust.", REF[8725] + " §3.10");
    }
    if (header.kid === undefined) {
      add("info", "kid-missing", "kid", "No kid. That's allowed, but with no key ID the API can't pick the right key from a JWKS, which makes key rotation harder.", REF[7519] + " §5");
    } else if (typeof header.kid === "string" && /(\.\.\/|[;'"`]|\x00|\s(or|union)\s)/i.test(header.kid)) {
      add("warn", "kid-injection", "kid", "kid contains characters that look like a path or a query (" + JSON.stringify(header.kid) + "). If your API uses kid to find a file or run a lookup, this is how it gets attacked.", REF[8725] + " §3.10");
    }
    if (header.crit !== undefined) {
      add("warn", "crit", "crit", "The header marks " + JSON.stringify(header.crit) + " as critical. Your API must reject the token unless it understands every one of them.", "RFC 7515 §4.1.11");
    }
    if (header.zip !== undefined) {
      add("warn", "zip", "zip", "zip on a signed token isn't defined, and compression before encryption can leak data.", REF[8725] + " §3.6");
    }

    // ---- Payload ----------------------------------------------------------

    if (access) {
      REQUIRED_AT_CLAIMS.forEach(function (c) {
        if (payload[c] === undefined) {
          add("error", "missing-" + c, c, c + " is missing. RFC 9068 requires it in every access token.", REF[9068] + " §2.2");
        }
      });
    } else {
      if (payload.exp === undefined) {
        add("warn", "missing-exp", "exp", "There's no exp, so this token never expires.", REF[7519] + " §4.1.4");
      }
    }

    ["exp", "nbf", "iat"].forEach(function (c) {
      if (payload[c] !== undefined && !isNumericDate(payload[c])) {
        add("error", c + "-type", c, c + " should be a number of seconds since 1970. It's " + JSON.stringify(payload[c]) + ".", REF[7519] + " §2, §4.1");
      }
    });

    if (isNumericDate(payload.exp)) {
      if (payload.exp > 1e11) {
        add("error", "exp-millis", "exp", "exp looks like milliseconds, not seconds. Read as seconds it's thousands of years away.", REF[7519] + " §2");
      } else if (now - leeway >= payload.exp) {
        add("error", "expired", "exp", "Expired " + describeSeconds(now - payload.exp) + " ago.", REF[7519] + " §4.1.4");
      }
    }
    if (isNumericDate(payload.nbf) && payload.nbf > now + leeway) {
      add("error", "not-yet-valid", "nbf", "Not valid for another " + describeSeconds(payload.nbf - now) + " (nbf).", REF[7519] + " §4.1.5");
    }
    if (isNumericDate(payload.iat) && payload.iat > now + leeway) {
      add("error", "iat-future", "iat", "Issued " + describeSeconds(payload.iat - now) + " in the future. Either a clock is wrong or the token was made by hand.", REF[7519] + " §4.1.6");
    }
    if (isNumericDate(payload.exp) && isNumericDate(payload.iat) && payload.exp <= 1e11) {
      var life = payload.exp - payload.iat;
      if (life <= 0) {
        add("error", "lifetime-negative", "exp", "exp is at or before iat, so this token was never valid.", REF[7519] + " §4.1.4");
      } else if (life > Number(opts.maxLifetimeSeconds)) {
        add("warn", "lifetime-long", "exp", "Lives " + describeSeconds(life) + ". A stolen access token works until it expires, so keep lifetimes short (an hour or less is common) and use refresh tokens.", REF[8725] + " §3.10; RFC 9700 §4.10");
      }
    }

    if (payload.aud !== undefined) {
      var auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (
        auds.some(function (a) {
          return typeof a !== "string";
        })
      ) {
        add("error", "aud-type", "aud", "aud should be a string or a list of strings.", REF[7519] + " §4.1.3");
      }
      if (opts.audience && opts.audience.length) {
        var hit = auds.some(function (a) {
          return opts.audience.indexOf(a) !== -1;
        });
        if (!hit) {
          add("error", "aud-mismatch", "aud", "aud is " + JSON.stringify(payload.aud) + ", not " + opts.audience.join(" or ") + ". This token was minted for a different API.", REF[7519] + " §4.1.3; " + REF[9068] + " §4");
        }
      } else if (auds.length > 1) {
        add("info", "aud-many", "aud", "The token is good for " + auds.length + " audiences. Every one of those APIs can replay it to the others.", REF[8725] + " §3.9");
      }
    }

    if (payload.iss !== undefined) {
      if (typeof payload.iss !== "string") {
        add("error", "iss-type", "iss", "iss should be a string.", REF[7519] + " §4.1.1");
      } else {
        if (opts.issuer && payload.iss !== opts.issuer) {
          add("error", "iss-mismatch", "iss", "iss is " + payload.iss + ", not the issuer you trust (" + opts.issuer + "). Compare it exactly, character for character.", REF[8725] + " §3.8; " + REF[9068] + " §4");
        }
        if (/^http:/i.test(payload.iss)) {
          add("warn", "iss-http", "iss", "The issuer is a plain-HTTP URL. Issuers should be https.", "OpenID Connect Discovery §3");
        }
      }
    }

    if (payload.scope !== undefined && typeof payload.scope !== "string") {
      add("warn", "scope-type", "scope", "scope should be one space-separated string, like \"read:pay write:pay\". It's " + (Array.isArray(payload.scope) ? "a list" : typeof payload.scope) + ". Some APIs will read it wrong.", REF[9068] + " §2.2.3");
    } else if (typeof payload.scope === "string" && /(^|\s)(\*|admin|all)(\s|$)/i.test(payload.scope)) {
      add("info", "scope-broad", "scope", "scope includes \"" + payload.scope.match(/(^|\s)(\*|admin|all)(\s|$)/i)[2] + "\". Check the client really needs that much.", "RFC 9700 §2.3");
    }

    if (access && payload.sub !== undefined && payload.client_id !== undefined && typeof payload.sub !== "string") {
      add("error", "sub-type", "sub", "sub should be a string.", REF[7519] + " §4.1.2");
    }
    if (payload.jti !== undefined && typeof payload.jti !== "string") {
      add("warn", "jti-type", "jti", "jti should be a string.", REF[7519] + " §4.1.7");
    }

    if (payload.nonce !== undefined && access) {
      add("info", "nonce", "nonce", "There's a nonce, which belongs in ID tokens. Check this isn't an ID token being used as an access token.", REF[8725] + " §3.11");
    }

    Object.keys(payload).forEach(function (key) {
      if (SENSITIVE.test(key)) {
        add("warn", "sensitive-claim", key, "The payload has a claim called " + key + ". Anyone holding the token can read the payload; signing doesn't hide it.", REF[8725] + " §3.6");
      }
    });

    return finish(result);
  }

  var ORDER = { error: 0, warn: 1, info: 2 };

  function finish(result) {
    result.findings.sort(function (a, b) {
      return ORDER[a.level] - ORDER[b.level];
    });
    var s = { error: 0, warn: 0, info: 0 };
    result.findings.forEach(function (f) {
      s[f.level]++;
    });
    s.pass = s.error === 0;
    result.summary = s;
    return result;
  }

  // ---- Command line ---------------------------------------------------------

  function cli(argv) {
    var args = argv.slice(2);
    var opts = {};
    var json = false;
    var token = null;
    var failOn = "error";
    for (var i = 0; i < args.length; i++) {
      var a = args[i];
      var next = function () {
        return args[++i];
      };
      if (a === "--aud" || a === "--audience") opts.audience = next().split(",");
      else if (a === "--iss" || a === "--issuer") opts.issuer = next();
      else if (a === "--alg" || a === "--algorithms") opts.algorithms = next();
      else if (a === "--key-hosts") opts.trustedKeyHosts = next();
      else if (a === "--leeway") opts.leewaySeconds = Number(next());
      else if (a === "--max-lifetime") opts.maxLifetimeSeconds = Number(next());
      else if (a === "--profile") opts.profile = next();
      else if (a === "--now") opts.now = Number(next());
      else if (a === "--fail-on") failOn = next();
      else if (a === "--json") json = true;
      else if (a === "-h" || a === "--help") return help();
      else if (a[0] === "-" && a !== "-") {
        process.stderr.write("Unknown option " + a + "\n");
        process.exit(2);
      } else token = a;
    }

    function run(t) {
      var r = lint(t, opts);
      if (json) {
        process.stdout.write(JSON.stringify(r, null, 2) + "\n");
      } else {
        r.findings.forEach(function (f) {
          var tag = f.level === "error" ? "ERROR" : f.level === "warn" ? "WARN " : "INFO ";
          process.stdout.write(tag + "  " + (f.claim ? "[" + f.claim + "] " : "") + f.message + (f.ref ? "  (" + f.ref + ")" : "") + "\n");
        });
        process.stdout.write(
          (r.findings.length ? "\n" : "") +
            r.summary.error + " errors, " + r.summary.warn + " warnings, " + r.summary.info + " notes. Signature not verified.\n"
        );
      }
      var fail = r.summary.error > 0 || (failOn === "warn" && r.summary.warn > 0);
      process.exit(fail ? 1 : 0);
    }

    if (token && token !== "-") return run(token);
    if (process.stdin.isTTY) return help();
    var buf = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", function (c) {
      buf += c;
    });
    process.stdin.on("end", function () {
      run(buf);
    });
  }

  function help() {
    process.stdout.write(
      [
        "Usage: node jwt-lint.js <token> [options]",
        "       echo $TOKEN | node jwt-lint.js [options]",
        "",
        "Checks a JWT access token against RFC 7519, RFC 8725 and RFC 9068.",
        "Exits 1 if any errors are found (or warnings, with --fail-on warn).",
        "",
        "  --aud <a,b>          audiences your API accepts",
        "  --iss <url>          the issuer your API trusts",
        "  --alg <RS256,ES256>  algorithms your API accepts",
        "  --key-hosts <hosts>  hosts allowed in jku / x5u",
        "  --leeway <seconds>   clock skew allowed (default 60)",
        "  --max-lifetime <s>   warn above this lifetime (default 3600)",
        "  --profile jwt        skip the RFC 9068 access-token rules",
        "  --now <seconds>      check as if it were this time",
        "  --fail-on warn       also fail on warnings",
        "  --json               print the full result as JSON",
        "",
        "The signature is not verified.",
        "",
      ].join("\n")
    );
  }

  if (typeof require !== "undefined" && typeof module !== "undefined" && require.main === module) {
    cli(process.argv);
  }

  return { lint: lint, defaults: DEFAULTS, cli: cli };
});
