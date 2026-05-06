# Contributing

This project is a deliberate invitation: the PowerShell code in this repo is a
proof of concept, and the goal is for contributors to help carry it forward into
a production-grade Zero Trust OT gateway. Pull requests are welcome.

## Licensing of contributions

This project is licensed under the **Apache License 2.0** (see [`LICENSE`](LICENSE)).

By submitting a pull request, you agree that your contribution is licensed under
the same terms. This is the standard "inbound = outbound" rule from §5 of the
Apache 2.0 license: anything you submit is offered under the project's license,
without any additional terms, unless you explicitly say otherwise in the PR.

If you cannot make that grant — for example, because your employer owns the
rights to the code you want to contribute and has not authorized you to release
it under Apache 2.0 — please open an issue rather than a PR so we can sort it
out before any code changes hands.

## What kinds of contributions are wanted

The most valuable contributions, roughly in order:

1. **A port of the admission engine to C# (ASP.NET Core) or F#.** See the
   "Production target language" section of the README for the rationale. Keep
   the functional-core / imperative-shell split that the PowerShell version has.
2. **A real transport layer.** The PoC stops at issuing a session ID; the
   `TODO for SWE` comment in `Request-OtAccess.ps1` marks where the tunnel
   should open. WireGuard, a TCP reverse proxy (YARP), or an SSH forward all fit.
3. **A device-registry backend** that is not a flat JSON file — likely backed
   by a database or a CMDB integration, with a small admin UI.
4. **Audit-log sinks** beyond the local JSONL file: SIEM forwarding, signed
   append-only storage, etc. CMMC assessors will care about the integrity of
   this log.
5. **More tests.** The PowerShell core has Pester coverage; the production port
   should match or exceed it.

If you have an idea that does not fit one of these, open an issue first to
discuss scope before doing the work.

## Pull request expectations

- **One logical change per PR.** Smaller is easier to review.
- **Tests for new logic.** The functional-core / imperative-shell split exists
  precisely so that the decision logic can be unit-tested without a Graph
  tenant. Keep it that way.
- **No surprise dependencies.** If your change requires a new package, call
  that out in the PR description and explain why.
- **Be explicit about behavior changes.** Anything that changes what gets
  written to the audit log — fields, format, ordering — needs a clear
  description, because that log is the compliance evidence artifact.

## Code review

PRs will be reviewed before merge. Review may be slow; this is a side project
intended to attract collaborators, not a funded effort with an SLA. Patience
appreciated.
