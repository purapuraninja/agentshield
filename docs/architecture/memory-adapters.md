# Memory adapter contract

AgentShield memory audit uses contract version `1`. An adapter declares its capabilities and exposes
connection testing, cursor-based inventory pages, and a deterministic SHA-256 checkpoint. An adapter
created in `audit` mode must declare `readOnlyAudit: true`, must declare source mutation and snapshot
restore as unsupported, and must not expose `planMutation`, `applyMutation`, or `restoreSnapshot`.

`validateMemoryAdapter()` is the conformance entry point. It checks the contract version, connection,
record schema, unique external IDs, cursor progress, checkpoint format, and the absence of a write
surface in audit mode. Built-in JSON, JSONL, Markdown, and SQLite inputs use this contract. SQLite is
opened with Node's read-only database mode.

## Incremental assessment

Unary detector results are stored locally in `.agentshield/memory-cache.json` with mode `0600` writes.
Reuse requires an exact match on source, adapter ID, external ID, content hash, full normalized-record
fingerprint, detector version, privacy mode, and UTC date bucket. The full-record fingerprint prevents
metadata-only changes from being missed; the date bucket prevents stale freshness results from being
reused indefinitely.

Cache entries contain only redacted findings and numeric assessments. Each cached finding and
assessment is schema-validated before reuse. A missing, corrupt, or unwritable cache never prevents a
fresh audit. Exact duplicates, near duplicates, conflicts, and corroboration are recomputed against
the complete current inventory on every audit because they depend on other records.

The local quarantine sidecar is separate from source mutation. Built-in audit adapters intentionally
do not claim write capabilities. Future PostgreSQL or vector adapters must implement and test an
explicit remediation-mode surface before source-store mutation can be enabled.
