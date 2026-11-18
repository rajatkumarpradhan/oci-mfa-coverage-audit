import unittest
from datetime import date, timedelta

from mfa_audit.model import ExportError, User, parse_date
from mfa_audit.rules import (
    exit_code,
    rule_admin_without_mfa,
    rule_console_without_mfa,
    rule_dormant_enabled,
    rule_groupless,
    run_all,
)

AS_OF = date(2026, 11, 19)


def user(utype="console", mfa=True, enabled=True, last_login_days=5, groups=("dev",)):
    return User(
        ocid="ocid1.user.oc1..x",
        name="u",
        user_type=utype,
        mfa_enrolled=mfa,
        enabled=enabled,
        last_login=(AS_OF - timedelta(days=last_login_days)) if last_login_days is not None else None,
        groups=tuple(groups),
    )


class TestMfa001(unittest.TestCase):
    def test_fires_admin_console_no_mfa(self):
        out = rule_admin_without_mfa((user(mfa=False, groups=("Network-Admins",)),), AS_OF)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "HIGH")

    def test_quiet_admin_with_mfa(self):
        self.assertEqual(rule_admin_without_mfa((user(groups=("admins",)),), AS_OF), [])

    def test_quiet_disabled(self):
        self.assertEqual(rule_admin_without_mfa((user(mfa=False, enabled=False, groups=("admins",)),), AS_OF), [])

    def test_quiet_api_only(self):
        self.assertEqual(rule_admin_without_mfa((user(utype="api_only", mfa=False, groups=("admins",)),), AS_OF), [])


class TestMfa002(unittest.TestCase):
    def test_fires_non_admin_console_no_mfa(self):
        out = rule_console_without_mfa((user(mfa=False),), AS_OF)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].severity, "MEDIUM")

    def test_admin_not_double_counted(self):
        self.assertEqual(rule_console_without_mfa((user(mfa=False, groups=("admins",)),), AS_OF), [])


class TestMfa003(unittest.TestCase):
    def test_fires_over_90_days(self):
        out = rule_dormant_enabled((user(last_login_days=120),), AS_OF)
        self.assertEqual(len(out), 1)

    def test_boundary_90_quiet(self):
        self.assertEqual(rule_dormant_enabled((user(last_login_days=90),), AS_OF), [])

    def test_null_login_fires(self):
        out = rule_dormant_enabled((user(last_login_days=None),), AS_OF)
        self.assertEqual(len(out), 1)
        self.assertIn("no login recorded", out[0].detail)

    def test_service_account_out_of_scope(self):
        self.assertEqual(rule_dormant_enabled((user(utype="service", last_login_days=None),), AS_OF), [])

    def test_disabled_quiet(self):
        self.assertEqual(rule_dormant_enabled((user(last_login_days=400, enabled=False),), AS_OF), [])


class TestMfa004(unittest.TestCase):
    def test_fires_zero_groups(self):
        self.assertEqual(len(rule_groupless((user(groups=()),), AS_OF)), 1)

    def test_grouped_quiet(self):
        self.assertEqual(rule_groupless((user(),), AS_OF), [])


class TestAggregation(unittest.TestCase):
    def test_exit_2_on_high(self):
        self.assertEqual(exit_code(run_all((user(mfa=False, groups=("admins",)),), AS_OF)), 2)

    def test_exit_1_medium_only(self):
        self.assertEqual(exit_code(run_all((user(mfa=False),), AS_OF)), 1)

    def test_exit_0_clean(self):
        self.assertEqual(exit_code(run_all((user(),), AS_OF)), 0)


class TestParsing(unittest.TestCase):
    def test_parse_date_ok(self):
        self.assertEqual(parse_date("2026-03-04", "t"), date(2026, 3, 4))

    def test_parse_date_bad(self):
        with self.assertRaises(ExportError):
            parse_date("04/03/2026", "t")


if __name__ == "__main__":
    unittest.main()
