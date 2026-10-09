# Usage guide

iam-access-reviewer is a personal portfolio project: a command-line
access-review analyzer for IAM account exports in pure Python 3 (standard
library only). It has never been deployed at any employer — it exists to
demonstrate security-automation skills.

## Install

Nothing to install beyond Python 3.10+. Clone the repo and run from its root:

```bash
git clone https://github.com/dheerajmkit/iam-access-reviewer.git
cd iam-access-reviewer
```

The test suite needs pytest:

```bash
pip install -r requirements.txt
pytest
```

## Input CSV

The reviewer consumes a CSV export of IAM users/accounts with this header:

```csv
username,user_type,last_login,mfa_enabled,policies,owner,owner_active
```

| Column        | Meaning                                                      |
| ------------- | ------------------------------------------------------------ |
| `username`    | Account name (required)                                      |
| `user_type`   | `human` or `service`                                         |
| `last_login`  | Last interactive login, `YYYY-MM-DD`; empty = never          |
| `mfa_enabled` | `true` / `false`                                             |
| `policies`    | Semicolon-separated policy names or action grants, e.g. `ReadOnlyAccess;iam:*` |
| `owner`       | Account owner (name or email)                                |
| `owner_active`| `true` / `false` — is the owner still with the org?          |

A 15-account sample covering every finding type ships in
`data/sample_users.csv` (all data fictional).

## Running a review

```bash
# JSON report (default)
python3 iam_review.py data/sample_users.csv

# Markdown report for reviewers
python3 iam_review.py data/sample_users.csv --format md --out report.md

# CSV of findings for spreadsheets / ticketing imports
python3 iam_review.py data/sample_users.csv --format csv --out findings.csv

# All three formats at once
python3 iam_review.py data/sample_users.csv --format all --out reports/review

# Repeatable runs (pins "today" instead of using the system date)
python3 iam_review.py data/sample_users.csv --today 2026-10-07

# Custom dormancy window
python3 iam_review.py data/sample_users.csv --dormant-days 60
```

Exit codes: `0` = no findings, `1` = findings present, `2` = usage/IO
error. Use the exit code to gate CI or scheduled review jobs.

## Checks and severity model

| Check                      | Triggers on                                              | Severity |
| -------------------------- | -------------------------------------------------------- | -------- |
| `dormant`                  | Human, no login in 90+ days (or never)                   | medium / high for admins |
| `no_mfa`                   | Human without MFA                                        | medium / critical for admins |
| `excessive_privilege`      | Admin policy (`AdministratorAccess`, …) or wildcard action (`*`, `s3:*`) | high / critical with missing MFA |
| `broad_privilege`          | Broad managed policy (`PowerUserAccess`)                 | medium |
| `orphaned`                 | Owner no longer active                                   | medium / high for admins |
| `service_interactive_login`| Service account with an interactive login                | high |

Severity escalates with context: an admin account without MFA is `critical`
rather than `medium`; a dormant admin is `high` rather than `medium`.

## Report contents

Every report carries an **executive summary**: accounts scanned vs. with
findings, total and critical/high counts, findings grouped by check type,
the top three risks, and a recommended action per finding type.

## CI

`.github/workflows/ci.yml` runs on every push and pull request: it byte-
compiles all sources, installs pytest, runs the suite on Python 3.10/3.11/
3.12, and smoke-tests the CLI against the sample data.
