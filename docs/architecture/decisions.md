# Architecture decisions

## ADR-001 — TypeScript local-first core

Status: accepted. The CLI, scanner, reports, memory auditor, runtime store, API, and dashboard use
TypeScript. Python remains an external adapter boundary only when its ecosystem materially improves
analysis. Versioned JSON is the integration boundary.

## ADR-002 — Deterministic analysis before models

Status: accepted. Production findings originate from deterministic rules. Optional model assistance
is outside the local MVP and can never be the sole cause of deletion, mutation, or blocking.

## ADR-003 — Filesystem evidence store for Community edition

Status: accepted. Canonical JSON and JSONL under `.agentshield/` provide a portable local store.
Runtime events are append-only; remediation events use a hash chain. PostgreSQL is reserved for a
deployed multi-tenant control plane.

## ADR-004 — Reversible quarantine sidecar

Status: accepted. Quarantine does not mutate the source store. A local sidecar excludes records from
subsequent AgentShield audits while preserving a mode-0600 snapshot. Restore changes sidecar state
and retains audit evidence.

## ADR-005 — Loopback-only local control plane

Status: accepted. The API binds to `127.0.0.1`, limits bodies, rejects non-loopback browser origins,
and never enables cloud upload by default. Authentication and tenant isolation are mandatory before
any non-loopback deployment.

## ADR-006 — Jailbreak detection is evidence-precise and advisory-aware

Status: accepted. Jailbreak and persona-switching content is detected by deterministic rules
(`AS-SC-028` framework artifacts, `AS-SC-029` known personas) at high severity with medium
confidence. Distinctive artifacts (activation tokens, mode names, unlock profiles) fire standalone;
generic or polysemous terms ("developer mode", "god mode", research terms such as "deceptive
alignment" or "reward hacking") only fire when they co-occur with jailbreak intent on the same
line, so security-education text and gaming or tooling documentation do not produce findings. In
persona templates the same patterns are advisory warnings only — the operator owns the persona and
decides — while memory records are handled by the memory detectors. No jailbreak finding ever
automatically blocks, deletes, or rewrites content; it enters the review queue.
