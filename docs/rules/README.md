# Rule catalog

`AS-SC-*` identifies supply-chain rules; `AS-ME-*` identifies memory rules; `AS-SC-900` means
analysis was incomplete. Run `agentshield rules list` and `agentshield explain <rule-id>` for the
canonical title, severity, remediation, owner, review date, and known limitations.

Rules are intentionally conservative. A finding is evidence for review, not proof of malicious
intent. `AS-SC-001` is taint-lite: secret access and a network sink in one file trigger a critical
finding even if static analysis cannot prove value flow.
