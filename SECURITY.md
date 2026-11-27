# Security Policy

`mcp-shield` is a security tool — it audits other people's MCP server
configurations — so its own security is treated seriously. This policy
covers vulnerabilities **in this repository**: the auditor itself.

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability. Report it
privately, either way:

- GitHub's private vulnerability reporting:
  <https://github.com/gravion-ux/mcp-shield/security/advisories/new>
- Email: priyanshukumarthakur937@gmail.com

Please include:

- A one- or two-sentence description of the issue.
- The version or commit SHA it affects.
- The smallest reproduction you have — a minimal config/tools file
  that triggers it is ideal.
- The impact you believe it has.

You can expect an acknowledgement within a few days.

## Disclosure timing

Please allow **90 days** for a fix to be released before any public
disclosure. If a fix ships earlier, coordinated disclosure can happen
as soon as the fixed version is available.

## Scope

In scope — the auditor itself, for example:

- mcp-shield executing, importing, or launching anything from a file
  it is auditing. It is static-analysis only by design; any path that
  breaks that rule is a vulnerability.
- A crafted config or tools file that crashes the auditor in a way
  that hides findings, or that makes a dangerous configuration pass
  silently (a check bypass with real impact — include the config that
  should have been flagged).
- Secrets or file contents from an audited file being written
  somewhere they do not belong (reports must reference findings, not
  exfiltrate audited material).

Out of scope:

- A missing check for a misconfiguration nobody has written yet —
  that is a feature request; please open a normal issue or PR (see
  CONTRIBUTING.md, "Anatomy of a check").
- Vulnerabilities in an MCP server or client that mcp-shield was
  pointed at — those belong to that project's owner.

## Supported versions

Only the current `main` branch and the latest release are supported.
Older commits are kept for history, not for backports.

## Repository hygiene

GitHub secret scanning and push protection are enabled for this
repository. Dependabot checks Python and GitHub Actions dependencies
weekly, and CodeQL runs on pushes, pull requests, and a weekly schedule.
Never commit real MCP credentials or private server configurations; use
synthetic examples that reproduce the check without exposing secrets.
