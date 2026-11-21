(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };

  function b64url(obj) {
    var s = btoa(unescape(encodeURIComponent(JSON.stringify(obj))));
    return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  // Samples are built at click time so their dates are always current.
  // The signature part is filler: this tool never verifies signatures.
  function sample(flawed) {
    var now = Math.floor(Date.now() / 1000);
    var header = { alg: "RS256", typ: "at+jwt", kid: "2026-01" };
    var payload = {
      iss: "https://login.example.com",
      sub: "u-1042",
      aud: "https://api.example.com",
      client_id: "payroll-web",
      iat: now - 120,
      exp: now + 780,
      jti: "6f1c2a9e",
      scope: "read:payslips",
    };
    if (flawed) {
      header = { alg: "HS256", typ: "JWT", jku: "https://keys.example.net/jwks.json" };
      payload.aud = "https://reports.example.com";
      payload.exp = now - 3600 * 5;
      payload.iat = now - 3600 * 29;
      delete payload.jti;
      payload.scope = ["read:payslips", "admin"];
    }
    $("token").value = b64url(header) + "." + b64url(payload) + ".ZmFrZS1zaWduYXR1cmU";
    $("aud").value = "https://api.example.com";
    $("iss").value = "https://login.example.com";
    $("alg").value = "RS256";
    $("hosts").value = "login.example.com";
    run();
  }

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function run() {
    var r = JwtLint.lint($("token").value, {
      audience: $("aud").value.trim() ? $("aud").value.split(",").map(function (s) { return s.trim(); }) : null,
      issuer: $("iss").value.trim() || null,
      algorithms: $("alg").value.trim() || null,
      trustedKeyHosts: $("hosts").value.trim() || null,
      maxLifetimeSeconds: (Number($("life").value) || 60) * 60,
      profile: $("profile").value,
    });
    var out = $("results");
    out.textContent = "";
    out.appendChild(el("p", "label", "Findings"));

    var sum = el("div", "summary");
    if (r.summary.error === 0) sum.appendChild(el("span", "count ok", "No errors"));
    else sum.appendChild(el("span", "count error", r.summary.error + (r.summary.error === 1 ? " error" : " errors")));
    if (r.summary.warn) sum.appendChild(el("span", "count warn", r.summary.warn + (r.summary.warn === 1 ? " warning" : " warnings")));
    if (r.summary.info) sum.appendChild(el("span", "count info", r.summary.info + (r.summary.info === 1 ? " note" : " notes")));
    out.appendChild(sum);

    if (r.findings.length) {
      var ul = el("ul", "findings");
      r.findings.forEach(function (f) {
        var li = el("li", "finding " + f.level);
        var head = el("div", "head");
        head.appendChild(el("span", "lvl", f.level === "warn" ? "warning" : f.level === "info" ? "note" : "error"));
        if (f.claim) head.appendChild(el("code", null, f.claim));
        li.appendChild(head);
        li.appendChild(el("p", null, f.message));
        if (f.ref) li.appendChild(el("div", "ref", f.ref));
        ul.appendChild(li);
      });
      out.appendChild(ul);
    }

    if (r.header) {
      var hl = el("p", "label", "Header");
      hl.style.marginTop = "18px";
      out.appendChild(hl);
      out.appendChild(el("pre", "json", JSON.stringify(r.header, null, 2)));
    }
    if (r.payload) {
      var pl = el("p", "label", "Payload");
      pl.style.marginTop = "14px";
      out.appendChild(pl);
      var text = JSON.stringify(r.payload, null, 2);
      ["exp", "iat", "nbf"].forEach(function (c) {
        if (typeof r.payload[c] === "number" && r.payload[c] < 1e11) {
          text = text.replace(new RegExp('("' + c + '": ' + r.payload[c] + ")"), "$1  // " + new Date(r.payload[c] * 1000).toISOString());
        }
      });
      out.appendChild(el("pre", "json", text));
    }
  }

  $("check").addEventListener("click", run);
  $("sample-bad").addEventListener("click", function () { sample(true); });
  $("sample-good").addEventListener("click", function () { sample(false); });
  $("token").addEventListener("input", function () { if ($("token").value.trim().split(".").length >= 3) run(); });
})();
