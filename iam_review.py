#!/usr/bin/env python3
"""
iam-access-reviewer
===================
A command-line access-review analyzer for IAM account exports.

Reads a CSV export of IAM users/accounts and flags risky access patterns:

  * dormant accounts - no interactive login in 90+ days (configurable)
  * missing MFA       - human accounts without MFA enabled

Produces a graded findings report as JSON. Standard library only,
Python 3.10+.

CSV format (header row required)::

  username,user_type,last_login,mfa_enabled,policies,owner,owner_active

  user_type     human | service
  last_login    YYYY-MM-DD (empty = never logged in)
  mfa_enabled   true | false
  policies      semicolon-separated policy names, e.g. "ReadOnlyAccess;iam:*"
  owner         account owner (name or email)
  owner_active  true | false (is the owner still with the org?)

Exit codes: 0 = no findings, 1 = findings present, 2 = usage/IO error.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import date, datetime

DEFAULT_DORMANT_DAYS = 90

# Managed policy names treated as full administrative access.
ADMIN_POLICY_NAMES = frozenset(
    {"administratoraccess", "admin", "superuser", "rootaccess"}
)

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def parse_bool(value: str) -> bool:
    """Parse a truthy/falsy CSV cell into a bool. Raises ValueError if unknown."""
    normalized = value.strip().lower()
    if normalized in {"true", "1", "yes", "y"}:
        return True
    if normalized in {"false", "0", "no", "n", ""}:
        return False
    raise ValueError(f"cannot parse boolean from {value!r}")


def parse_date(value: str) -> date | None:
    """Parse a YYYY-MM-DD cell into a date. Empty cells mean 'never' (None)."""
    text = value.strip()
    if not text:
        return None
    try:
        return date.fromisoformat(text)
    except ValueError:
        raise ValueError(
            f"cannot parse date from {value!r}; expected YYYY-MM-DD"
        ) from None


def load_accounts(path: str) -> list[dict]:
    """Load and normalize the IAM account export CSV."""
    required = {
        "username",
        "user_type",
        "last_login",
        "mfa_enabled",
        "policies",
        "owner",
        "owner_active",
    }
    accounts: list[dict] = []
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError(f"{path}: CSV has no header row")
        missing = required - {name.strip() for name in reader.fieldnames}
        if missing:
            raise ValueError(
                f"{path}: missing required columns: {sorted(missing)}"
            )
        for lineno, row in enumerate(reader, start=2):
            row = {(k or "").strip(): (v or "") for k, v in row.items()}
            username = row["username"].strip()
            if not username:
                raise ValueError(f"{path}:{lineno}: username is required")
            user_type = row["user_type"].strip().lower()
            if user_type not in {"human", "service"}:
                raise ValueError(
                    f"{path}:{lineno}: user_type must be 'human' or 'service', "
                    f"got {row['user_type']!r}"
                )
            policies = [
                token.strip() for token in row["policies"].split(";") if token.strip()
            ]
            accounts.append(
                {
                    "username": username,
                    "user_type": user_type,
                    "last_login": parse_date(row["last_login"]),
                    "mfa_enabled": parse_bool(row["mfa_enabled"]),
                    "policies": policies,
                    "owner": row["owner"].strip(),
                    "owner_active": parse_bool(row["owner_active"]),
                }
            )
    return accounts


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def is_admin(account: dict) -> bool:
    """True when the account holds a full-administrator managed policy."""
    return any(
        policy.lower() in ADMIN_POLICY_NAMES for policy in account["policies"]
    )


def check_dormant(
    account: dict, dormant_days: int, today: date
) -> dict | None:
    """Flag human accounts with no login in `dormant_days`+ days (or never)."""
    if account["user_type"] != "human":
        return None
    last_login = account["last_login"]
    if last_login is None:
        detail = "account has never logged in"
        days = None
    else:
        days = (today - last_login).days
        if days < dormant_days:
            return None
        detail = f"last login {last_login.isoformat()} ({days} days ago)"
    return {
        "username": account["username"],
        "check": "dormant",
        "severity": "high" if is_admin(account) else "medium",
        "detail": detail,
        "days_inactive": days,
    }


def check_mfa(account: dict) -> dict | None:
    """Flag human accounts without MFA enabled."""
    if account["user_type"] != "human":
        return None
    if account["mfa_enabled"]:
        return None
    return {
        "username": account["username"],
        "check": "no_mfa",
        "severity": "critical" if is_admin(account) else "medium",
        "detail": "human account without MFA enabled",
        "days_inactive": None,
    }


CHECKS_DAY1 = ("dormant", "no_mfa")


# ---------------------------------------------------------------------------
# Review engine
# ---------------------------------------------------------------------------

def run_review(
    accounts: list[dict],
    dormant_days: int = DEFAULT_DORMANT_DAYS,
    today: date | None = None,
) -> dict:
    """Run every check over every account and return the graded report."""
    today = today or date.today()
    findings: list[dict] = []
    for account in accounts:
        findings.append(check_dormant(account, dormant_days, today))
        findings.append(check_mfa(account))
    findings = [finding for finding in findings if finding is not None]
    findings.sort(
        key=lambda f: (
            -SEVERITY_ORDER[f["severity"]],
            f["username"],
            f["check"],
        )
    )
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for finding in findings:
        summary[finding["severity"]] += 1
    summary["total_findings"] = len(findings)
    summary["accounts_with_findings"] = len(
        {finding["username"] for finding in findings}
    )
    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "accounts_scanned": len(accounts),
        "dormant_days": dormant_days,
        "summary": summary,
        "findings": findings,
    }


def write_json(report: dict, path: str) -> None:
    """Write the report as pretty-printed JSON."""
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze an IAM account export (CSV) and flag risky "
        "access patterns: dormant accounts and missing MFA."
    )
    parser.add_argument("csv_file", help="path to the IAM account export CSV")
    parser.add_argument(
        "--dormant-days",
        type=int,
        default=DEFAULT_DORMANT_DAYS,
        help=f"days without login before an account is dormant "
        f"(default: {DEFAULT_DORMANT_DAYS})",
    )
    parser.add_argument(
        "--out",
        default="iam-review-report.json",
        help="output report path (default: iam-review-report.json)",
    )
    parser.add_argument(
        "--today",
        default=None,
        help="override 'today' as YYYY-MM-DD (for repeatable reviews)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.dormant_days < 1:
        parser.error("--dormant-days must be at least 1")
    today = parse_date(args.today) if args.today else None

    try:
        accounts = load_accounts(args.csv_file)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = run_review(accounts, dormant_days=args.dormant_days, today=today)

    try:
        write_json(report, args.out)
    except OSError as exc:
        print(f"error: cannot write {args.out}: {exc}", file=sys.stderr)
        return 2

    summary = report["summary"]
    print(
        f"scanned {report['accounts_scanned']} accounts, "
        f"{summary['total_findings']} findings "
        f"(critical={summary['critical']}, high={summary['high']}, "
        f"medium={summary['medium']}, low={summary['low']}) -> {args.out}"
    )
    return 1 if summary["total_findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
