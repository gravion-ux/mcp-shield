# Contributing to mcp-shield

Thanks for helping! `mcp-shield` is a **defensive** security auditor
for MCP (Model Context Protocol) server configurations and tool
definitions — the files people paste into their AI clients. It flags
tool poisoning, rug pulls, over-broad grants and unpinned execution
*before* a server is ever started. It only reads files; it never
starts an MCP server or executes audited code.

The most valuable contributions are **new checks** (with tests and a
README table entry), broader secret/token format coverage, and tests.

## Ground rules

- **Zero runtime dependencies — hard rule.** Pure Python standard
  library. PRs adding a runtime dependency will not be merged.
- **Static analysis only.** Never execute, import, or launch anything
  being audited. If a check needs to run the target, it does not
  belong in mcp-shield.
- **No false-positive spam.** A check that fires on normal, healthy
  configurations trains users to ignore the tool. Every new check
  needs a "clean" test case proving it stays quiet on a reasonable
  config, not just a "dirty" case proving it fires.

## Development setup

Requires Python 3.9 or newer.

```bash
git clone https://github.com/gravion-ux/mcp-shield.git
cd mcp-shield
pip install -e ".[dev]"
```

The package uses a `src/` layout (`src/mcp_shield/`); the root
`conftest.py` puts `src/` on the path for pytest.

## Running the tests

```bash
python -m pytest -q
```

With coverage (this is what CI runs):

```bash
python -m pytest -q --cov=mcp_shield --cov-report=xml
```

Smoke test — the bundled example is deliberately risky, so the audit
**must** flag it (exit `1` with findings is success here):

```bash
mcp-shield audit --config examples/risky-config.json \
    --tools examples/risky-tools.json --format json
```

## Anatomy of a check

Checks live in `src/mcp_shield/checks.py`. Config checks take
`(name, server)`; tool checks take a tool dict (or the full tool list
for cross-tool checks like name shadowing). Each returns `Finding`s
with:

- `check_id` — stable, kebab-case (`secret-in-env`,
  `tool-name-confusable`, …). IDs are API: reports and baselines refer
  to them, so never rename an existing one.
- `severity` — `critical` / `high` / `medium` / `low`, calibrated
  against the existing table in the README.
- A concrete `remediation` — tell the user exactly what to change.

To add a check:

1. Implement it in `checks.py` and wire it into `audit_server()` or
   `audit_tools()`.
2. Add tests in `tests/test_checks.py`: one dirty case that must
   fire, one clean case that must not.
3. Add a row to the Checks table in the README with the same
   `check_id` and severity.

Token-format additions go in `SECRET_VALUE_PATTERNS` (regex + human
label) — include a test with a realistic-looking (fake) sample of the
format, and a placeholder value (`your-...`, `${...}`) proving the
placeholder exemption still holds.

## Code style

- Module docstring at the top; `from __future__ import annotations`;
  type hints; double quotes.
- Regexes get a comment saying what they catch and why — the poison
  patterns in `checks.py` are the model to follow.
- Tests are plain pytest functions, deterministic, offline, using
  inline dict fixtures or the files in `examples/`.

## Proposing a bigger change

New report formats, baseline/pin format changes, or anything that
changes existing `check_id`s or severities: **open an issue first**.
New checks and pattern additions can go straight to a pull request.

## Pull request workflow

1. Fork and branch from `main`: `check/<check-id>` for new checks,
   `feat/<short-name>`, `fix/<short-name>`, `docs/<short-name>`
   otherwise.
2. Run the full suite and the risky-example smoke test locally.
3. Open the PR against `main` with: what changed, why, how you
   tested it — and for a new check, an example of the real-world
   misconfiguration it catches.
4. CI must be green — Python 3.10, 3.11 and 3.12 plus the smoke test
   (CI asserts the risky example produces findings with a non-zero
   risk score).
5. One logical change per PR.
