"""Unit tests for iam-access-reviewer (pytest)."""

import json
import os
import sys
from datetime import date

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import iam_review

TODAY = date(2026, 10, 7)
SAMPLE_CSV = os.path.join(os.path.dirname(__file__), "..", "data", "sample_users.csv")


def make_account(**overrides):
    account = {
        "username": "u.test",
        "user_type": "human",
        "last_login": date(2026, 9, 28),
        "mfa_enabled": True,
        "policies": ["ReadOnlyAccess"],
        "owner": "u.test@acme.example",
        "owner_active": True,
    }
    account.update(overrides)
    return account


# --- parsing ---------------------------------------------------------------

def test_parse_bool_variants():
    assert iam_review.parse_bool("true") is True
    assert iam_review.parse_bool(" TRUE ") is True
    assert iam_review.parse_bool("yes") is True
    assert iam_review.parse_bool("1") is True
    assert iam_review.parse_bool("false") is False
    assert iam_review.parse_bool("No") is False
    assert iam_review.parse_bool("0") is False
    with pytest.raises(ValueError):
        iam_review.parse_bool("maybe")


def test_parse_date_valid_and_empty():
    assert iam_review.parse_date("2026-02-10") == date(2026, 2, 10)
    assert iam_review.parse_date("") is None
    assert iam_review.parse_date("   ") is None
    with pytest.raises(ValueError):
        iam_review.parse_date("10/02/2026")


def test_load_accounts_sample():
    accounts = iam_review.load_accounts(SAMPLE_CSV)
    assert len(accounts) == 15
    first = accounts[0]
    assert first["username"] == "j.morrison"
    assert first["user_type"] == "human"
    assert first["last_login"] == date(2026, 9, 28)
    assert first["mfa_enabled"] is True
    assert first["policies"] == ["ReadOnlyAccess"]
    assert first["owner_active"] is True


def test_load_accounts_missing_column(tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text("username,user_type\nj.morrison,human\n")
    with pytest.raises(ValueError, match="missing required columns"):
        iam_review.load_accounts(str(bad))


def test_load_accounts_bad_user_type(tmp_path):
    bad = tmp_path / "bad.csv"
    bad.write_text(
        "username,user_type,last_login,mfa_enabled,policies,owner,owner_active\n"
        "x.bot,robot,,false,,o@acme.example,true\n"
    )
    with pytest.raises(ValueError, match="user_type"):
        iam_review.load_accounts(str(bad))


# --- dormant ----------------------------------------------------------------

def test_dormant_old_login():
    finding = iam_review.check_dormant(
        make_account(last_login=date(2026, 2, 10)), 90, TODAY
    )
    assert finding is not None
    assert finding["check"] == "dormant"
    assert finding["severity"] == "medium"
    assert finding["days_inactive"] == 239


def test_dormant_never_logged_in():
    finding = iam_review.check_dormant(
        make_account(last_login=None), 90, TODAY
    )
    assert finding is not None
    assert "never logged in" in finding["detail"]


def test_dormant_recent_login_clean():
    assert (
        iam_review.check_dormant(
            make_account(last_login=date(2026, 9, 28)), 90, TODAY
        )
        is None
    )


def test_dormant_ignores_service_accounts():
    assert (
        iam_review.check_dormant(
            make_account(user_type="service", last_login=None), 90, TODAY
        )
        is None
    )


def test_dormant_admin_escalates():
    finding = iam_review.check_dormant(
        make_account(last_login=date(2026, 1, 1),
                     policies=["AdministratorAccess"]),
        90,
        TODAY,
    )
    assert finding["severity"] == "high"


# --- MFA --------------------------------------------------------------------

def test_no_mfa_flagged():
    finding = iam_review.check_mfa(make_account(mfa_enabled=False))
    assert finding is not None
    assert finding["check"] == "no_mfa"
    assert finding["severity"] == "medium"


def test_mfa_enabled_clean():
    assert iam_review.check_mfa(make_account(mfa_enabled=True)) is None


def test_no_mfa_ignores_service_accounts():
    assert (
        iam_review.check_mfa(
            make_account(user_type="service", mfa_enabled=False)
        )
        is None
    )


def test_no_mfa_admin_is_critical():
    finding = iam_review.check_mfa(
        make_account(mfa_enabled=False, policies=["AdministratorAccess"])
    )
    assert finding["severity"] == "critical"


# --- excessive privilege -----------------------------------------------------

def test_admin_policy_flagged():
    findings = iam_review.check_excessive_privilege(
        make_account(policies=["AdministratorAccess"])
    )
    assert len(findings) == 1
    assert findings[0]["check"] == "excessive_privilege"
    assert findings[0]["severity"] == "high"
    assert "AdministratorAccess" in findings[0]["detail"]


def test_admin_policy_no_mfa_is_critical():
    findings = iam_review.check_excessive_privilege(
        make_account(policies=["AdministratorAccess"], mfa_enabled=False)
    )
    assert findings[0]["severity"] == "critical"


def test_wildcard_actions_flagged():
    findings = iam_review.check_excessive_privilege(
        make_account(policies=["iam:*", "s3:*"])
    )
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert "wildcard" in findings[0]["detail"]


def test_bare_star_flagged():
    findings = iam_review.check_excessive_privilege(make_account(policies=["*"]))
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"


def test_scoped_actions_clean():
    findings = iam_review.check_excessive_privilege(
        make_account(policies=["s3:GetObject", "ec2:DescribeInstances"])
    )
    assert findings == []


def test_broad_policy_medium():
    findings = iam_review.check_excessive_privilege(
        make_account(policies=["PowerUserAccess"])
    )
    assert len(findings) == 1
    assert findings[0]["check"] == "broad_privilege"
    assert findings[0]["severity"] == "medium"


def test_admin_and_wildcard_both_reported():
    findings = iam_review.check_excessive_privilege(
        make_account(policies=["AdministratorAccess", "s3:*"])
    )
    assert len(findings) == 2


# --- orphaned / service -------------------------------------------------------

def test_orphaned_flagged():
    finding = iam_review.check_orphaned(make_account(owner_active=False))
    assert finding is not None
    assert finding["check"] == "orphaned"
    assert finding["severity"] == "medium"


def test_active_owner_clean():
    assert iam_review.check_orphaned(make_account(owner_active=True)) is None


def test_service_interactive_login_flagged():
    finding = iam_review.check_service_interactive(
        make_account(user_type="service", last_login=date(2026, 9, 30))
    )
    assert finding is not None
    assert finding["check"] == "service_interactive_login"
    assert finding["severity"] == "high"


def test_service_without_login_clean():
    assert (
        iam_review.check_service_interactive(
            make_account(user_type="service", last_login=None)
        )
        is None
    )


def test_human_login_not_service_finding():
    assert (
        iam_review.check_service_interactive(
            make_account(user_type="human", last_login=date(2026, 9, 30))
        )
        is None
    )


# --- review engine ------------------------------------------------------------

def test_run_review_sample_counts():
    accounts = iam_review.load_accounts(SAMPLE_CSV)
    report = iam_review.run_review(accounts, dormant_days=90, today=TODAY)
    assert report["accounts_scanned"] == 15
    assert report["summary"]["critical"] == 3
    assert report["summary"]["high"] == 6
    assert report["summary"]["medium"] == 10
    assert report["summary"]["low"] == 0
    assert report["summary"]["total_findings"] == 19
    assert report["summary"]["accounts_with_findings"] == 11


def test_findings_sorted_by_severity():
    accounts = iam_review.load_accounts(SAMPLE_CSV)
    report = iam_review.run_review(accounts, dormant_days=90, today=TODAY)
    severities = [
        iam_review.SEVERITY_ORDER[f["severity"]] for f in report["findings"]
    ]
    assert severities == sorted(severities, reverse=True)


def test_worst_case_account():
    accounts = iam_review.load_accounts(SAMPLE_CSV)
    report = iam_review.run_review(accounts, dormant_days=90, today=TODAY)
    nguyen = [f for f in report["findings"] if f["username"] == "t.nguyen"]
    checks = {f["check"] for f in nguyen}
    assert checks == {"dormant", "no_mfa", "excessive_privilege", "orphaned"}


# --- report writers -----------------------------------------------------------

def test_write_json_roundtrip(tmp_path):
    accounts = iam_review.load_accounts(SAMPLE_CSV)
    report = iam_review.run_review(accounts, dormant_days=90, today=TODAY)
    out = str(tmp_path / "report.json")
    iam_review.write_json(report, out)
    loaded = json.loads(open(out).read())
    assert loaded["summary"] == report["summary"]
    assert len(loaded["findings"]) == len(report["findings"])


def test_write_markdown_structure(tmp_path):
    accounts = iam_review.load_accounts(SAMPLE_CSV)
    report = iam_review.run_review(accounts, dormant_days=90, today=TODAY)
    out = str(tmp_path / "report.md")
    iam_review.write_markdown(report, out)
    text = open(out).read()
    assert text.startswith("# IAM Access Review Report")
    assert "## Summary" in text
    assert "## Findings" in text
    assert "### CRITICAL" in text
    assert "t.nguyen" in text


def test_write_markdown_clean_report(tmp_path):
    report = iam_review.run_review([], today=TODAY)
    out = str(tmp_path / "clean.md")
    iam_review.write_markdown(report, out)
    assert "No findings" in open(out).read()


# --- CLI ----------------------------------------------------------------------

def test_cli_json_exit_code(tmp_path, capsys):
    out = str(tmp_path / "r.json")
    code = iam_review.main(
        [SAMPLE_CSV, "--today", "2026-10-07", "--out", out]
    )
    assert code == 1  # findings present
    assert os.path.exists(out)


def test_cli_clean_exit_code(tmp_path):
    clean = tmp_path / "clean.csv"
    clean.write_text(
        "username,user_type,last_login,mfa_enabled,policies,owner,owner_active\n"
        "j.morrison,human,2026-09-28,true,ReadOnlyAccess,j@acme.example,true\n"
    )
    code = iam_review.main(
        [str(clean), "--today", "2026-10-07",
         "--out", str(tmp_path / "r.json")]
    )
    assert code == 0


def test_cli_markdown_format(tmp_path):
    out = str(tmp_path / "r.md")
    code = iam_review.main(
        [SAMPLE_CSV, "--today", "2026-10-07", "--format", "md", "--out", out]
    )
    assert code == 1
    assert open(out).read().startswith("# IAM Access Review Report")


def test_cli_missing_file():
    assert iam_review.main(["/nonexistent/users.csv"]) == 2


# --- executive summary (day 3) ------------------------------------------------

def test_executive_summary_contents():
    accounts = iam_review.load_accounts(SAMPLE_CSV)
    report = iam_review.run_review(accounts, dormant_days=90, today=TODAY)
    summary = report["executive_summary"]
    assert summary["accounts_scanned"] == 15
    assert summary["accounts_with_findings"] == 11
    assert summary["total_findings"] == 19
    assert summary["critical_and_high"] == 9
    assert summary["counts_by_check"]["dormant"] == 5
    assert summary["counts_by_check"]["excessive_privilege"] == 5
    assert len(summary["top_risks"]) == 3
    # top risks are the highest-severity findings, in report order
    assert summary["top_risks"][0]["severity"] == "critical"
    assert summary["top_risks"][0]["username"] == "l.garcia"
    assert len(summary["recommended_actions"]) > 0
    assert any("MFA" in action for action in summary["recommended_actions"])


def test_executive_summary_clean_report():
    report = iam_review.run_review([], today=TODAY)
    summary = report["executive_summary"]
    assert summary["total_findings"] == 0
    assert summary["top_risks"] == []
    assert summary["recommended_actions"] == []


# --- CSV export (day 3) ---------------------------------------------------------

def test_write_csv_roundtrip(tmp_path):
    import csv

    accounts = iam_review.load_accounts(SAMPLE_CSV)
    report = iam_review.run_review(accounts, dormant_days=90, today=TODAY)
    out = str(tmp_path / "findings.csv")
    iam_review.write_csv(report, out)
    with open(out, newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 19
    assert set(rows[0].keys()) == {
        "username",
        "check",
        "severity",
        "detail",
        "days_inactive",
    }
    assert rows[0]["severity"] == "critical"  # sorted first


def test_write_markdown_has_executive_summary(tmp_path):
    accounts = iam_review.load_accounts(SAMPLE_CSV)
    report = iam_review.run_review(accounts, dormant_days=90, today=TODAY)
    out = str(tmp_path / "report.md")
    iam_review.write_markdown(report, out)
    text = open(out).read()
    assert "## Executive Summary" in text
    assert "### Top risks" in text
    assert "### Recommended actions" in text
    assert "### Findings by check" in text


def test_cli_csv_format(tmp_path):
    out = str(tmp_path / "findings.csv")
    code = iam_review.main(
        [SAMPLE_CSV, "--today", "2026-10-07", "--format", "csv", "--out", out]
    )
    assert code == 1
    assert open(out).read().splitlines()[0].startswith("username,check")


def test_cli_all_formats(tmp_path):
    code = iam_review.main(
        [
            SAMPLE_CSV,
            "--today",
            "2026-10-07",
            "--format",
            "all",
            "--out",
            str(tmp_path / "review"),
        ]
    )
    assert code == 1
    assert os.path.exists(str(tmp_path / "review.json"))
    assert os.path.exists(str(tmp_path / "review.md"))
    assert os.path.exists(str(tmp_path / "review.csv"))


def test_resolve_outputs():
    assert iam_review.resolve_outputs("json", None) == [
        ("json", "iam-review-report.json")
    ]
    assert iam_review.resolve_outputs("md", "r.md") == [("md", "r.md")]
    assert iam_review.resolve_outputs("all", None) == [
        ("json", "iam-review-report.json"),
        ("md", "iam-review-report.md"),
        ("csv", "iam-review-report.csv"),
    ]
    assert iam_review.resolve_outputs("all", "out/review") == [
        ("json", "out/review.json"),
        ("md", "out/review.md"),
        ("csv", "out/review.csv"),
    ]
