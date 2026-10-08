# iam-access-reviewer

A command-line access-review analyzer for IAM account exports, written in
pure Python 3 (standard library only). It reads a CSV of IAM users/accounts
and flags risky access patterns — dormant accounts, missing MFA, excessive
privilege, orphaned accounts, and interactive service-account logins — then
produces a graded findings report as JSON or Markdown.

This is a **personal portfolio project** exploring IAM hygiene automation. It
is a learning exercise, not a production tool, and it has never been deployed
at any employer. All sample data is fictional.

## Quickstart

No dependencies to install — the standard library is all you need:

```bash
python3 iam_review.py data/sample_users.csv --format md --out report.md
```

A finding looks like this in the JSON report:

```json
{
  "username": "t.nguyen",
  "check": "no_mfa",
  "severity": "critical",
  "detail": "human account without MFA enabled",
  "days_inactive": null
}
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

## CSV format

Header row required:

```csv
username,user_type,last_login,mfa_enabled,policies,owner,owner_active
j.morrison,human,2026-09-28,true,ReadOnlyAccess,j.morrison@acme.example,true
svc-deploy,service,,false,AdministratorAccess,platform-team@acme.example,true
```

`last_login` is `YYYY-MM-DD` (empty = never logged in); `policies` is a
semicolon-separated list of managed-policy names or `service:action` grants.

## Options

```bash
python3 iam_review.py users.csv --format json --out report.json
python3 iam_review.py users.csv --format md --out report.md
python3 iam_review.py users.csv --dormant-days 60 --today 2026-10-07
```

## Tests

```bash
pip install -r requirements.txt   # pytest only
pytest
```
