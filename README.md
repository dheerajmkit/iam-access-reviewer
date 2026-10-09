# iam-access-reviewer

[![ci](https://github.com/dheerajmkit/iam-access-reviewer/actions/workflows/ci.yml/badge.svg)](https://github.com/dheerajmkit/iam-access-reviewer/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![stdlib](https://img.shields.io/badge/deps-stdlib%20only-green.svg)](requirements.txt)

A command-line access-review analyzer for IAM account exports, written in
pure Python 3 (standard library only). It reads a CSV of IAM users/accounts
and flags risky access patterns — dormant accounts, missing MFA, excessive
privilege, orphaned accounts, and interactive service-account logins — then
produces a graded findings report as JSON, Markdown, or CSV, each with an
executive summary for reviewers and leadership.

This is a **personal portfolio project** exploring IAM hygiene automation. It
is a learning exercise, not a production tool, and it has never been deployed
at any employer. All sample data is fictional.

## Quickstart

No dependencies to install — the standard library is all you need:

```bash
python3 iam_review.py data/sample_users.csv --format md --out report.md
```

Example output:

```
scanned 15 accounts, 19 findings (critical=3, high=6, medium=10, low=0) -> report.md
```

The Markdown report opens with an executive summary:

```markdown
## Executive Summary

11 of 15 accounts have findings (19 total, 9 critical/high).

### Top risks

1. **l.garcia** [critical/excessive_privilege] — wildcard action grant: *
2. **t.nguyen** [critical/excessive_privilege] — administrator policy attached: AdministratorAccess
3. **t.nguyen** [critical/no_mfa] — human account without MFA enabled

### Recommended actions

- Replace administrator and wildcard grants with scoped least-privilege policies.
- Enforce MFA for all human accounts; block console access for accounts without MFA.
- Move service accounts to machine credentials (access keys / IAM roles) and disable console access.
```

The exit code is `1` when findings are present and `0` when the export is
clean, so the reviewer can gate a CI step or a periodic access-review job.

## Checks

- **dormant** — human account with no login in 90+ days (configurable via
  `--dormant-days`); graded `medium`, or `high` for admin accounts.
- **no_mfa** — human account without MFA enabled; graded `medium`, or
  `critical` for admin accounts.
- **excessive_privilege** — administrator managed policy (`AdministratorAccess`
  and friends) or wildcard action grants (`*`, `s3:*`, `iam:*`); graded `high`,
  or `critical` when combined with missing MFA.
- **broad_privilege** — broad managed policies such as `PowerUserAccess`;
  graded `medium`.
- **orphaned** — account whose owner is no longer active; graded `medium`, or
  `high` for admin accounts.
- **service_interactive_login** — service account with an interactive login;
  graded `high`.

Severity escalates with context: an admin account without MFA is `critical`
rather than `medium`; a dormant admin is `high` rather than `medium`.

## CSV format

Header row required:

```csv
username,user_type,last_login,mfa_enabled,policies,owner,owner_active
j.morrison,human,2026-09-28,true,ReadOnlyAccess,j.morrison@acme.example,true
svc-deploy,service,,false,AdministratorAccess,platform-team@acme.example,true
```

`last_login` is `YYYY-MM-DD` (empty = never logged in); `policies` is a
semicolon-separated list of managed-policy names or `service:action` grants.
A 15-account sample covering every finding type ships in
`data/sample_users.csv`.

## Options

```bash
python3 iam_review.py users.csv --format json --out report.json
python3 iam_review.py users.csv --format md --out report.md
python3 iam_review.py users.csv --format csv --out findings.csv
python3 iam_review.py users.csv --format all --out reports/review   # all three
python3 iam_review.py users.csv --dormant-days 60 --today 2026-10-07
```

## Tests

```bash
pip install -r requirements.txt   # pytest only
pytest
```

## CI

`.github/workflows/ci.yml` runs on every push and pull request: byte-compiles
all sources, installs pytest, runs the suite on Python 3.10 / 3.11 / 3.12,
and smoke-tests the CLI against the sample data. Full usage details live in
[docs/USAGE.md](docs/USAGE.md).
