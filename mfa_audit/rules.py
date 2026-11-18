"""MFA001-MFA004 rules."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from .model import DORMANT_DAYS


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str  # HIGH | MEDIUM | LOW
    user: str
    detail: str


def rule_admin_without_mfa(users: tuple, as_of: date) -> list:
    """MFA001 HIGH: enabled console user in an admin-named group without MFA."""
    del as_of
    return [
        Finding("MFA001", "HIGH", u.name,
                f"enabled console user in admin-named group(s) {[g for g in u.groups if 'admin' in g.lower()]} "
                f"with no MFA enrolled in this export")
        for u in users if u.enabled and u.is_console() and u.in_admin_group() and not u.mfa_enrolled
    ]


def rule_console_without_mfa(users: tuple, as_of: date) -> list:
    """MFA002 MEDIUM: enabled console user (non-admin) without MFA."""
    del as_of
    return [
        Finding("MFA002", "MEDIUM", u.name,
                "enabled console user with no MFA enrolled in this export")
        for u in users
        if u.enabled and u.is_console() and not u.in_admin_group() and not u.mfa_enrolled
    ]


def rule_dormant_enabled(users: tuple, as_of: date) -> list:
    """MFA003 MEDIUM: enabled CONSOLE user with no login in DORMANT_DAYS.

    The export's last_login field tracks console logins; api_only and service
    accounts authenticate via API keys, a different signal, so they are out of
    scope for this rule.
    """
    out = []
    for u in users:
        if not u.enabled or not u.is_console():
            continue
        if u.last_login is None:
            out.append(
                Finding("MFA003", "MEDIUM", u.name,
                        "enabled console user with no login recorded at all in this export; dormant access")
            )
        elif (as_of - u.last_login).days > DORMANT_DAYS:
            out.append(
                Finding("MFA003", "MEDIUM", u.name,
                        f"enabled console user last logged in {(as_of - u.last_login).days} days ago (> {DORMANT_DAYS}); "
                        f"dormant access recorded in this export")
            )
    return out


def rule_groupless(users: tuple, as_of: date) -> list:
    """MFA004 LOW: enabled user in zero groups."""
    del as_of
    return [
        Finding("MFA004", "LOW", u.name,
                "enabled user belongs to zero groups; worth an access review")
        for u in users if u.enabled and not u.groups
    ]


ALL_RULES = (
    rule_admin_without_mfa,
    rule_console_without_mfa,
    rule_dormant_enabled,
    rule_groupless,
)

_SEVERITY_RANK = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def run_all(users: tuple, as_of: date) -> list:
    findings = []
    for rule in ALL_RULES:
        findings.extend(rule(users, as_of))
    findings.sort(key=lambda x: (_SEVERITY_RANK[x.severity], x.rule, x.user))
    return findings


def exit_code(findings: list) -> int:
    if any(f.severity == "HIGH" for f in findings):
        return 2
    if findings:
        return 1
    return 0
