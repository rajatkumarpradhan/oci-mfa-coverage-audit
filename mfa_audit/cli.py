"""python -m mfa_audit.cli EXPORT [--as-of YYYY-MM-DD]"""

from __future__ import annotations

import argparse
import sys
from datetime import date, datetime

from .model import ExportError, load_export
from .rules import exit_code, run_all


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mfa-coverage-audit",
        description="Audit an offline export of IAM users for MFA coverage gaps and dormant access.",
    )
    p.add_argument("export", help="path to the JSON export")
    p.add_argument("--as-of", default=None, help="reference date YYYY-MM-DD (default: today, UTC)")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.as_of:
        try:
            as_of = datetime.strptime(args.as_of, "%Y-%m-%d").date()
        except ValueError:
            print(f"error: --as-of {args.as_of!r} is not YYYY-MM-DD", file=sys.stderr)
            return 2
    else:
        as_of = date.today()
    try:
        users = load_export(args.export)
    except ExportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    findings = run_all(users, as_of)
    enabled = sum(1 for u in users if u.enabled)
    with_mfa = sum(1 for u in users if u.enabled and u.is_console() and u.mfa_enrolled)
    print(
        f"MFA coverage audit as of {as_of.isoformat()} - {len(users)} user(s) "
        f"({enabled} enabled, {with_mfa} console users with MFA), {len(findings)} finding(s)"
    )
    for x in findings:
        print(f"[{x.severity:6s}] {x.rule} user={x.user}")
        print(f"         {x.detail}")
    code = exit_code(findings)
    print({0: "RESULT: clean", 1: "RESULT: warnings only", 2: "RESULT: HIGH findings present"}[code])
    return code


if __name__ == "__main__":
    raise SystemExit(main())
