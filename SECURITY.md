# Security policy

## Reporting a vulnerability

Please don't open a public issue for a security problem. Report it privately instead: **[Report a vulnerability](https://github.com/jamalsjones/jwt-lint/security/advisories/new)**. Only you and I can see the report.

Tell me what you found, how to reproduce it (a sample input is ideal), and what you think an attacker could do with it.

I maintain this on my own, so I can't promise a fixed response time. I'll reply, keep you posted while I work on a fix, and credit you in the advisory unless you'd rather I didn't.

## Supported versions

Only the latest commit on `main`. That's also what the hosted page at [https://jamalsjones.github.io/jwt-lint/](https://jamalsjones.github.io/jwt-lint/) runs. Fixes aren't backported.

## In scope

- Input that makes the page run script, or that gets a token you paste sent off the page (nothing is meant to leave it)
- A check that misses what this README says it flags, such as a token with `alg: none` that passes
- Input that makes the checker crash or hang
- Anything in the command-line tool or module that runs code or reads files it wasn't pointed at

## Out of scope

- A forged token that passes every check. The tool doesn't verify signatures, as the README says; that's your API's job.
- Findings that are about level (a warning you think should be an error). Open an ordinary issue for those.
