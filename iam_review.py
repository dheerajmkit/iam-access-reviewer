#!/usr/bin/env python3
"""
iam-access-reviewer
===================
A command-line access-review analyzer for IAM account exports.

Reads a CSV export of IAM users/accounts and flags risky access patterns:

  * dormant accounts          - no interactive login in 90+ days (configurable)
  * missing MFA                - human accounts without MFA enabled
  * excessive privilege        - admin managed policies, wildcard actions,
                                 broad managed policies
  * orphaned accounts          - owner is no longer active
  * service interactive login  - service accounts with interactive logins

Produces a graded findings report as JSON, Markdown, or CSV, each with an
executive summary (top risks, findings by check type, recommended actions).
Standard library only, Python 3.10+.

CSV format (header row required)::

  username,user_type,last_login,mfa_enabled,policies,owner,owner_active

  user_type     human | service
  last_login    YYYY-MM-DD (empty = never logged in)
  mfa_enabled   true | false
  policies      semicolon-separated policy names or action grants,
                e.g. "ReadOnlyAccess;iam:*"
  owner         account owner (name or email)
  owner_active  true | false (is the owner still with the org?)

Exit codes: 0 = no findings, 1 = findings present, 2 = usage/IO error.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from datetime import date, datetime

DEFAULT_DORMANT_DAYS = 90

# Managed policy names treated as full administrative access.
ADMIN_POLICY_NAMES = frozenset(
    {"administratoraccess", "admin", "superuser", "rootaccess"}
)

# Managed policies that are not full admin but still very broad.
BROAD_POLICY_NAMES = frozenset({"poweruseraccess"})

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Remediation guidance surfaced in the executive summary, keyed by check.
RECOMMENDED_ACTIONS = {
    "dormant": "Disable or remove dormant accounts after owner confirmation; "
    "require periodic access re-certification.",
    "no_mfa": "Enforce MFA for all human accounts; block console access for "
    "accounts without MFA.",
    "excessive_privilege": "Replace administrator and wildcard grants with "
    "scoped least-privilege policies.",
    "broad_privilege": "Review broad managed policies (e.g. PowerUserAccess) "
    "and scope them down where possible.",
    "orphaned": "Reassign or deprovision accounts whose owners have departed.",
    "service_interactive_login": "Move service accounts to machine "
    "credentials (access keys / IAM roles) and disable console access.",
}


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


def is_wildcard_action(policy: str) -> bool:
    """True for `*`-style action grants such as `*`, `s3:*`, or `iam:*`."""
    return policy == "*" or ":*" in policy


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


def check_excessive_privilege(account: dict) -> list[dict]:
    """Flag admin policies, wildcard action grants, and broad policies."""
    findings: list[dict] = []
    policies = account["policies"]
    no_mfa_human = (
        account["user_type"] == "human" and not account["mfa_enabled"]
    )

    admin_policies = sorted(
        {p for p in policies if p.lower() in ADMIN_POLICY_NAMES}
    )
    if admin_policies:
        findings.append(
            {
                "username": account["username"],
                "check": "excessive_privilege",
                "severity": "critical" if no_mfa_human else "high",
                "detail": "administrator policy attached: "
                + ", ".join(admin_policies),
                "days_inactive": None,
            }
        )

    wildcards = sorted({p for p in policies if is_wildcard_action(p)})
    if wildcards:
        findings.append(
            {
                "username": account["username"],
                "check": "excessive_privilege",
                "severity": "critical" if no_mfa_human else "high",
                "detail": "wildcard action grant: " + ", ".join(wildcards),
                "days_inactive": None,
            }
        )

    broad = sorted({p for p in policies if p.lower() in BROAD_POLICY_NAMES})
    if broad:
        findings.append(
            {
                "username": account["username"],
                "check": "broad_privilege",
                "severity": "medium",
                "detail": "broad managed policy attached: " + ", ".join(broad),
                "days_inactive": None,
            }
        )
    return findings


def check_orphaned(account: dict) -> dict | None:
    """Flag accounts whose owner is no longer active."""
    if account["owner_active"] or not account["owner"]:
        return None
    return {
        "username": account["username"],
        "check": "orphaned",
        "severity": "high" if is_admin(account) else "medium",
        "detail": f"owner {account['owner']} is no longer active",
        "days_inactive": None,
    }


def check_service_interactive(account: dict) -> dict | None:
    """Flag service accounts that have logged in interactively."""
    if account["user_type"] != "service":
        return None
    if account["last_login"] is None:
        return None
    return {
        "username": account["username"],
        "check": "service_interactive_login",
        "severity": "high",
        "detail": "service account logged in interactively on "
        f"{account['last_login'].isoformat()}; service accounts should "
        "use machine credentials (access keys / roles), not console logins",
        "days_inactive": None,
    }


# ---------------------------------------------------------------------------
# Review engine
# ---------------------------------------------------------------------------

def build_executive_summary(report: dict) -> dict:
    """Build the leadership-facing summary: top risks and remediations."""
    findings = report["findings"]
    summary = report["summary"]
    counts_by_check: dict[str, int] = {}
    for finding in findings:
        counts_by_check[finding["check"]] = (
            counts_by_check.get(finding["check"], 0) + 1
        )
    top_risks = [
        {
            "username": finding["username"],
            "check": finding["check"],
            "severity": finding["severity"],
            "detail": finding["detail"],
        }
        for finding in findings[:3]
    ]
    recommended_actions: list[str] = []
    for finding in findings:
        action = RECOMMENDED_ACTIONS.get(finding["check"])
        if action and action not in recommended_actions:
            recommended_actions.append(action)
    return {
        "accounts_scanned": report["accounts_scanned"],
        "accounts_with_findings": summary["accounts_with_findings"],
        "total_findings": summary["total_findings"],
        "critical_and_high": summary["critical"] + summary["high"],
        "counts_by_check": counts_by_check,
        "top_risks": top_risks,
        "recommended_actions": recommended_actions,
    }


def run_review(
    accounts: list[dict],
    dormant_days: int = DEFAULT_DORMANT_DAYS,
    today: date | None = None,
) -> dict:
    """Run every check over every account and return the graded report."""
    today = today or date.today()
    findings: list[dict] = []
    for account in accounts:
        single = (
            check_dormant(account, dormant_days, today),
            check_mfa(account),
            check_orphaned(account),
            check_service_interactive(account),
        )
        findings.extend(f for f in single if f is not None)
        findings.extend(check_excessive_privilege(account))
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
    report = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "accounts_scanned": len(accounts),
        "dormant_days": dormant_days,
        "summary": summary,
        "findings": findings,
    }
    report["executive_summary"] = build_executive_summary(report)
    return report


# ---------------------------------------------------------------------------
# Report writers
# ---------------------------------------------------------------------------

def write_json(report: dict, path: str) -> None:
    """Write the report as pretty-printed JSON."""
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")


def write_csv(report: dict, path: str) -> None:
    """Write the findings as CSV (one row per finding)."""
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["username", "check", "severity", "detail", "days_inactive"]
        )
        for finding in report["findings"]:
            writer.writerow(
                [
                    finding["username"],
                    finding["check"],
                    finding["severity"],
                    finding["detail"],
                    finding["days_inactive"]
                    if finding["days_inactive"] is not None
                    else "",
                ]
            )


def write_markdown(report: dict, path: str) -> None:
    """Write the report as a human-readable Markdown access-review document."""
    summary = report["summary"]
    exec_summary = report["executive_summary"]
    lines = [
        "# IAM Access Review Report",
        "",
        f"Generated: {report['generated_at']}",
        f"Accounts scanned: {report['accounts_scanned']} "
        f"(dormant threshold: {report['dormant_days']} days)",
        "",
        "## Executive Summary",
        "",
        f"{exec_summary['accounts_with_findings']} of "
        f"{exec_summary['accounts_scanned']} accounts have findings "
        f"({exec_summary['total_findings']} total, "
        f"{exec_summary['critical_and_high']} critical/high).",
        "",
        "### Top risks",
        "",
    ]
    if not exec_summary["top_risks"]:
        lines.append("No material risks identified.")
    else:
        for i, risk in enumerate(exec_summary["top_risks"], start=1):
            lines.append(
                f"{i}. **{risk['username']}** [{risk['severity']}/"
                f"{risk['check']}] — {risk['detail']}"
            )
    lines += ["", "### Recommended actions", ""]
    if not exec_summary["recommended_actions"]:
        lines.append("No remediation actions required.")
    else:
        for action in exec_summary["recommended_actions"]:
            lines.append(f"- {action}")
    lines += [
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for severity in ("critical", "high", "medium", "low"):
        lines.append(f"| {severity} | {summary[severity]} |")
    lines += [
        f"| **total** | **{summary['total_findings']}** |",
        "",
        "### Findings by check",
        "",
        "| Check | Count |",
        "| --- | --- |",
    ]
    for check, count in sorted(exec_summary["counts_by_check"].items()):
        lines.append(f"| {check} | {count} |")
    lines += [
        "",
        "## Findings",
        "",
    ]
    if not report["findings"]:
        lines.append("No findings. All reviewed accounts passed every check.")
    else:
        current_severity = None
        for finding in report["findings"]:
            if finding["severity"] != current_severity:
                current_severity = finding["severity"]
                lines += ["", f"### {current_severity.upper()}", ""]
            lines.append(
                f"- **{finding['username']}** [{finding['check']}] — "
                f"{finding['detail']}"
            )
    lines.append("")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

REPORT_FORMATS = ("json", "md", "csv")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze an IAM account export (CSV) and flag risky "
        "access patterns: dormant accounts, missing MFA, excessive "
        "privilege, orphaned accounts, and interactive service logins."
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
        "--format",
        choices=("json", "md", "markdown", "csv", "all"),
        default="json",
        help="report format: json, md, csv, or all (default: json)",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="output report path (default: iam-review-report.<ext>; with "
        "--format all, the extension is replaced per format)",
    )
    parser.add_argument(
        "--today",
        default=None,
        help="override 'today' as YYYY-MM-DD (for repeatable reviews)",
    )
    return parser


def resolve_outputs(fmt: str, out: str | None) -> list[tuple[str, str]]:
    """Map --format/--out to a list of (format, path) pairs to write."""
    formats = list(REPORT_FORMATS) if fmt == "all" else [fmt]
    outputs = []
    for one in formats:
        if out and fmt != "all":
            path = out
        else:
            base = os.path.splitext(out)[0] if out else "iam-review-report"
            path = f"{base}.{one}"
        outputs.append((one, path))
    return outputs


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.dormant_days < 1:
        parser.error("--dormant-days must be at least 1")
    today = parse_date(args.today) if args.today else None

    fmt = "md" if args.format == "markdown" else args.format
    outputs = resolve_outputs(fmt, args.out)

    try:
        accounts = load_accounts(args.csv_file)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = run_review(accounts, dormant_days=args.dormant_days, today=today)

    writers = {"json": write_json, "md": write_markdown, "csv": write_csv}
    written = []
    try:
        for one, path in outputs:
            writers[one](report, path)
            written.append(path)
    except OSError as exc:
        print(f"error: cannot write report: {exc}", file=sys.stderr)
        return 2

    summary = report["summary"]
    print(
        f"scanned {report['accounts_scanned']} accounts, "
        f"{summary['total_findings']} findings "
        f"(critical={summary['critical']}, high={summary['high']}, "
        f"medium={summary['medium']}, low={summary['low']}) -> "
        + ", ".join(written)
    )
    return 1 if summary["total_findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
