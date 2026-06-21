# ODRL Policy Set

This folder contains base ODRL JSON-LD policies that match the current `PolicyPurposeValidator` and `models.ODRLPolicy` schema.

The validator only evaluates:

- `action` values in each rule
- optional `constraint.purpose` values

Role tiering is therefore expressed through policy names, `assignee` values, and the allowed purposes documented in each file.

Policy levels included here:

1. `00-no-pii-observer.json` - very restrictive; limited to metadata, triage, and summary workflows.
2. `10-support-limited.json` - can work with operational data but is still blocked from broad access.
3. `20-privacy-analyst.json` - broader investigative access for approved review and compliance work.
4. `30-full-access.json` - permissive policy with no purpose gate, allowing all supported actions.

Use these as starting points and tighten or expand the purpose lists to match your real ODRL governance model.