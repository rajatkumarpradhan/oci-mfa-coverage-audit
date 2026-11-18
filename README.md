# oci-mfa-coverage-audit

**Category: custom portfolio tool.** Pure Python command-line auditor. It does **not** wire any
built-in OCI services together - it is the *custom* project in its daily pair (the built-in
services project is `oci-ootb-logging-retention-check`).

## The problem

Password-only console accounts are the soft underbelly of any tenancy, and the risk
concentrates where you look least: an admin who "will set up MFA tomorrow", a contractor
account nobody disabled, a user who has not logged in for months but still can. This tool
audits an **offline export** of IAM users and flags the coverage gaps recorded in that
export.

## What it does

Reads a JSON export (schema below, synthetic samples included) and applies four rules:

| Rule | Severity | Fires when |
| ---- | -------- | ---------- |
| MFA001 | HIGH | An enabled console user in a group whose name contains `admin` has no MFA enrolled. |
| MFA002 | MEDIUM | Any other enabled console user has no MFA enrolled. |
| MFA003 | MEDIUM | An enabled console user has no login recorded in the last 90 days, or none at all (dormant access recorded in the export). The `last_login` field tracks console logins only, so API-only and service accounts are out of scope for this rule. |
| MFA004 | LOW | An enabled user belongs to zero groups (access-review hygiene). |

Exit code: `2` if any HIGH finding, `1` if only MEDIUM/LOW, `0` when clean.

## Run it

```bash
python -m mfa_audit.cli samples/users_messy.json --as-of 2026-11-19   # exits 2, all 4 rules fire
python -m mfa_audit.cli samples/users_clean.json --as-of 2026-11-19   # exits 0
python -m unittest discover -s tests -v                               # 22 tests, stdlib only
```

`--as-of` fixes the reference date so dormancy math is reproducible; omit it for today (UTC).

## Export schema

```json
{
  "users": [
    {"ocid": "ocid1.user.oc1..u1", "name": "priya", "user_type": "console",
     "mfa_enrolled": true, "enabled": true, "last_login": "2026-11-15",
     "groups": ["network-admins"]}
  ]
}
```

`user_type` is `console`, `api_only`, or `service`. MFA findings apply to console users
only - API-only and service accounts do not authenticate with passwords at the console.

## Honest limits

- **Offline only**: the export is synthetic; nothing calls the OCI IAM API.
- Findings describe what the export records. MFA enrollment state, group membership and login
  history are only as complete as the export; a gap here is a prompt to verify, not proof of
  the live state.
- The 90-day dormancy window (MFA003) is a default, not OCI policy.
- `admin` group matching is a name-substring convention, not an OCI concept.
- MFA enrollment says nothing about phishing-resistant factors or session policies; those are
  outside this tool's scope.

## Project status

Built as a daily portfolio project. 22 unit tests, green locally and in CI
(`.github/workflows/ci.yml`, Python 3.10/3.11/3.12). No paid services, no live cloud calls.
