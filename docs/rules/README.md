# Rule catalog

`AS-SC-*` identifies supply-chain rules; `AS-ME-*` identifies memory rules; `AS-SC-900` means
analysis was incomplete. Run `agentshield rules list` and `agentshield explain <rule-id>` for the
canonical title, severity, remediation, owner, review date, and known limitations. Both the static
scanner rules and the memory detector rules are listed and explainable.

Rules are intentionally conservative. A finding is evidence for review, not proof of malicious
intent. `AS-SC-001` uses AST data-flow evidence for valid JavaScript/TypeScript. Languages still on
the conservative parser use same-file taint-lite fallback, and the finding metadata states which
analysis produced it.

## Golden quality gate

Every registered production rule has one true-positive and two safe negative fixtures in
`fixtures/rules/golden-cases.json`. Run `pnpm quality:rules` for the aggregate confusion matrix,
fixture precision/recall, metadata validation, per-rule status, and stale review detection. The full
`pnpm check` command includes this gate.

Fixture precision is a regression metric, not a claim about real-world precision. Public-corpus
evaluation remains necessary before release.

## Memory detectors

Memory rules (`AS-ME-*`) run inside the read-only memory auditor alongside the relational
duplicate, conflict, freshness, secret, PII, and integrity detectors. `AS-ME-010` flags
instruction-like untrusted text; `AS-ME-012` flags zero-width or bidirectional control characters
that can make reviewed text differ from interpreted text (parity with `AS-SC-026`); and `AS-ME-013`
flags instruction phrases hidden inside base64 blobs or contiguous HTML numeric entities. Encoded
detections match only the decoded payload against the instruction phrases, so a plain-text
instruction next to an unrelated entity does not fabricate an encoded-injection finding.
