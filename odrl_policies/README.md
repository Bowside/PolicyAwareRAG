# ODRL Policy Set

This directory contains ODRL 2.2 JSON-LD policy examples for a corporate PII environment.

The policy loader validates ODRL 2.2 JSON-LD policies that use standard `permission` and `prohibition` rules.

Policy levels included here:

1. `00-no-pii-observer.json` defines `business-observer`, limited to metadata review, routing, and triage.
2. `10-support-limited.json` defines `customer-support-specialist`, limited to case handling and incident triage.
3. `20-privacy-analyst.json` defines `privacy-compliance-analyst`, used for compliance, fraud, security, and privacy review.
4. `30-full-access.json` defines `pii-data-governance-admin`, with broad operational access for controlled administration.

Each policy uses a shared PII asset target and purpose-gated permissions, with explicit export prohibitions on the restricted tiers.

The retrieval layer expects document `securityMetadata` to align with the policy-derived keys below:

- `policyUid`: the normalized policy identifier.
- `policyRole`: the normalized assignee role.
- `policyTarget`: the normalized target asset identifier.
- `policyAction`: the requested action, normalized to lowercase.
- `policyPurpose`: the matched purpose constraint, when the permission rule includes one.

Policies without a purpose constraint still produce role, target, and action filters. The full-access policy therefore still scopes retrieval by policy identity and role, even when it has no explicit purpose gate.