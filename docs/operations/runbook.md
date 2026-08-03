# Local operations runbook

## Bad rule or false positive

Record the finding fingerprint, owner, reason, and expiry in a version-1 baseline. Never suppress by
rule ID alone. Re-run with `--baseline` and keep the unsuppressed canonical report as evidence.

## Parser regression

Treat `AS-SC-900` and partial status as non-passing in CI. Preserve the target hash, scanner version,
and sanitized error, then add a minimal fixture before changing the parser.

## Quarantine recovery

Inspect `.agentshield/quarantine.json` and `.agentshield/audit.jsonl`. Use `memory restore` with a new
actor and reason. Do not edit the sidecar manually; that breaks the audit trail.

## Credential evidence

Rotate the credential at its provider. Reports contain only masked fingerprints or redacted text,
but the original target and local quarantine snapshot may still contain the value.
