# Security boundaries

```text
untrusted target ──read-only──> scanner/memory adapter ──redacted schema──> reports
agent runtime ──hashed payload──> local event collector ──causal IDs──> evidence graph
reviewer ──explicit actor+reason──> quarantine sidecar ──hash-chain──> audit log
```

Target files, memory, event input, policy files, and MCP descriptions are untrusted. The static
scanner never follows symlinks or evaluates code. SQLite opens with `readOnly: true`. All API and CLI
boundaries validate canonical schemas before persisting or converting reports.

The local API is not an internet-facing service. A remote or shared deployment requires
authentication, authorization, tenant isolation, TLS, rate limiting, immutable backing storage,
backup/restore drills, and an independent security review.
