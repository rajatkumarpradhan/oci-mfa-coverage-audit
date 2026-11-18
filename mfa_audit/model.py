"""Data model + export loading for the MFA coverage audit."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import date, datetime


class ExportError(ValueError):
    """Raised when an export file is malformed."""


DORMANT_DAYS = 90
USER_TYPES = {"console", "api_only", "service"}


def parse_date(value: str, what: str) -> date:
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except (TypeError, ValueError) as exc:
        raise ExportError(f"invalid date for {what}: {value!r} (expected YYYY-MM-DD)") from exc


@dataclass(frozen=True)
class User:
    ocid: str
    name: str
    user_type: str
    mfa_enrolled: bool
    enabled: bool
    last_login: date | None
    groups: tuple = field(default_factory=tuple)

    def is_console(self) -> bool:
        return self.user_type == "console"

    def in_admin_group(self) -> bool:
        return any("admin" in g.lower() for g in self.groups)

    def dormant_days(self, as_of: date) -> int | None:
        if self.last_login is None:
            return None
        return (as_of - self.last_login).days


def load_export(path: str) -> tuple:
    with open(path, "r", encoding="utf-8") as fh:
        try:
            raw = json.load(fh)
        except json.JSONDecodeError as exc:
            raise ExportError(f"{path}: not valid JSON: {exc}") from exc
    if not isinstance(raw, dict) or not isinstance(raw.get("users"), list):
        raise ExportError(f"{path}: top level must be an object with a 'users' list")
    out = []
    for i, u in enumerate(raw["users"]):
        where = f"users[{i}]"
        for req in ("ocid", "name", "user_type"):
            if req not in u:
                raise ExportError(f"{where}: missing required field {req!r}")
        if u["user_type"] not in USER_TYPES:
            raise ExportError(f"{where}: user_type must be one of {sorted(USER_TYPES)}, got {u['user_type']!r}")
        last = u.get("last_login")
        out.append(
            User(
                ocid=u["ocid"],
                name=u["name"],
                user_type=u["user_type"],
                mfa_enrolled=bool(u.get("mfa_enrolled", False)),
                enabled=bool(u.get("enabled", True)),
                last_login=parse_date(last, f"{where}.last_login") if last else None,
                groups=tuple(u.get("groups", [])),
            )
        )
    return tuple(out)
