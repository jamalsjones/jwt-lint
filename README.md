# JWT lint

Paste an access token and see what an API should reject it for. It checks a JWT against [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) (JWT), [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725) (JWT best current practices) and [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) (the JWT profile for OAuth 2.0 access tokens), and cites the section for every finding.

**Use it in the browser:** [jamalsjones.github.io/jwt-lint](https://jamalsjones.github.io/jwt-lint/). The token is checked in the page and never sent anywhere.

## What it checks

| Area | Flags |
|---|---|
| Algorithm | `alg: none`, an algorithm outside your allow list, shared-secret (HS) algorithms on access tokens, a stripped signature |
| Token type | `typ` other than `at+jwt`, so an ID token can't pass as an access token |
| Keys | `jku` or `x5u` pointing at an untrusted host or plain HTTP, a key embedded in the header (`jwk`), a `kid` that looks like path traversal or injection |
| Time | expired, not yet valid, issued in the future, `exp` in milliseconds, lifetimes longer than your limit |
| Claims | missing `iss`, `exp`, `aud`, `sub`, `client_id`, `iat` or `jti`; wrong audience or issuer; `scope` as a list; claims that look like secrets |

Each finding is an **error** (reject the token), a **warning** (fix the issuer) or a **note** (worth knowing).

It doesn't verify the signature. That needs the issuer's key and is your API's job, so a token can pass every check here and still be forged. Use this to review what an issuer is minting, or to see why an API turned a token down.

## In a pipeline

`jwt-lint.js` is one file with no dependencies. The same file runs the browser page and the command line. It exits 1 when it finds an error, so it can fail a smoke test after an identity provider change.

```bash
node jwt-lint.js "$TOKEN" --aud https://api.example.com --iss https://login.example.com --alg RS256,ES256
echo "$TOKEN" | node jwt-lint.js --json
```

| Option | |
|---|---|
| `--aud a,b` | audiences your API accepts |
| `--iss url` | the issuer your API trusts (compared exactly) |
| `--alg RS256,ES256` | algorithms your API accepts |
| `--key-hosts host` | hosts allowed in `jku` / `x5u` |
| `--leeway 60` | clock skew in seconds |
| `--max-lifetime 3600` | warn above this lifetime in seconds |
| `--profile jwt` | skip the RFC 9068 access-token rules, for other JWTs |
| `--fail-on warn` | also fail on warnings |
| `--json` | print the full result |

Or use it as a module: `const { lint } = require("./jwt-lint.js")`.

## Make it yours

Fork it and change the defaults at the top of `jwt-lint.js` to your organization's standards: your issuer, your algorithms, your lifetime limit. Add a check by adding an `add(...)` call in `lint()` and a test in `test/`. Run the tests with `npm test` (Node 18 or later, nothing to install).

To host your own copy, turn on GitHub Pages for your fork (Settings → Pages → deploy from the `main` branch).

## Related

- [OIDC config check](https://github.com/jamalsjones/oidc-config-check): review what your identity provider advertises.
- [Leaver check](https://github.com/jamalsjones/leaver-check): find accounts that outlived the people who owned them.
- [Security games](https://jamalsjones.github.io/security-games/): Token Inspector is a game version of this tool.

## Author

Jamal Jones. Fifteen years leading enterprise identity. More at [jamalsjones.com](https://www.jamalsjones.com).

MIT licensed.
