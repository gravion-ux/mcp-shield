## What changed

<!-- One or two sentences. What is different after this pull request? -->

## Why

<!-- Link the issue it closes, or state the problem it solves. For a
     new check: the real-world misconfiguration it catches. -->

## How it was tested

<!-- The exact commands you ran and what they printed, e.g.
     `python -m pytest -q` (all passing) and the risky-example smoke
     test from CONTRIBUTING.md. -->

## Checklist

- [ ] Full test suite passes locally and CI is green
- [ ] For a new check: a dirty test case that fires **and** a clean test case that stays quiet are both included
- [ ] For a new check: the README Checks table has a row with the same `check_id` and severity
- [ ] No existing `check_id` renamed and no severity silently changed
- [ ] Nothing in the change executes, imports, or launches audited code (static analysis only)
- [ ] No new runtime dependency (standard library only)
- [ ] No real secrets or tokens anywhere in the diff (test samples are fake or placeholders)
- [ ] One logical change in this PR
