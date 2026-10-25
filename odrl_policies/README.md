# ODRL policies

This folder contains the JSON policy files loaded automatically by
`app/policy_guard.py`. There is no standalone command to run from this folder.
The loader reads every `*.json` file in sorted filename order and evaluates all
matching permissions and prohibitions.

## Policy model

The active roles are:

| Role | Typical permitted purposes | Additional behavior |
| --- | --- | --- |
| `business-observer` | `metadata_review`, `routing`, `triage`, `timeline_reconstruction`, `sentiment_analysis` | Cannot export or redact; answers must remove personal names through the semantic spokesperson review. |
| `customer-support-specialist` | `customer_support`, `case_management`, `incident_triage`, `complaint_handling`, `escalation_tracking` | Cannot export or redact; sensitive email addresses, phone numbers, and SSNs are redacted. |
| `privacy-compliance-analyst` | `compliance_review`, `fraud_detection`, `security_review`, `privacy_review`, `data_retention`, `insider_trading`, `whistleblower_protection` | May redact, but cannot export. |
| `pii-data-governance-admin` | Any purpose | Has unrestricted configured actions, including export. |

Configured actions are `retrieve`, `summarise`, `summarize`, `audit`, `redact`,
and `export`. Purpose-constrained permissions require an exact normalized
purpose match. Roles are normalized for case, spaces, and the
`urn:policyaware:role:` prefix. When several roles are supplied, output
protection uses the most restrictive recognized role.

To use the policies locally, start the application from the repository root:

```powershell
func start
```

To exercise policy loading and authorization, run the policy tests from the
repository root:

```powershell
python -m pytest -q tests/unit_tests/test_policy_guard_odrl.py
```

Keep policy filenames in this folder with the `.json` extension. The loader
reads all such files in sorted filename order.

Each policy entry should retain the ODRL `permission` and `prohibition` shape
used by the existing files. Changes should be covered by the policy unit tests,
especially for purpose mismatches, prohibited actions, unknown roles, and
redaction or spokesperson behavior.