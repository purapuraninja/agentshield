# AgentShield

AgentShield is a local-first security scanner and memory hygiene toolkit for AI agents. It inspects
skills, MCP configuration, prompts, scripts, and stored memory without executing target code. Every
finding includes deterministic evidence and remediation.

This repository implements the local Community product described in
[`AGENTSHIELD_DEVELOPMENT_PLAN.md`](./AGENTSHIELD_DEVELOPMENT_PLAN.md): static scanning, permission
mapping, policy-as-code, JSON/SARIF/HTML/AgentBOM reports, read-only memory auditing, reversible
quarantine, sanitized runtime events, a REST API, and a local dashboard.

## Quick start

Requirements: Node.js 22.13+ and Corepack.

```bash
corepack pnpm install
corepack pnpm build
node packages/cli/dist/cli.cjs scan fixtures/vulnerable --format terminal
```

During development:

```bash
corepack pnpm dev -- scan ./my-skill
corepack pnpm dev -- scan ./my-skill --format sarif --output agentshield.sarif
corepack pnpm dev -- scan ./my-skill --policy policies/default.yaml --ci
```

Exit codes are `0` for pass, `1` for operational failure, `2` for block/severity failure, `3` for
required review, and `4` for incomplete CI analysis.

## CLI

```text
agentshield scan <file-or-directory>
agentshield scan-mcp <config>
agentshield permissions <target>
agentshield diff <old> <new>
agentshield policy check <report.json> <policy.yaml>
agentshield report <report.json> --format html
agentshield rules list
agentshield explain AS-SC-001

agentshield memory audit <json|jsonl|markdown|sqlite>
agentshield memory quarantine <target> <memory-id> --actor <name> --reason <reason>
agentshield memory restore <target> <memory-id> --actor <name> --reason <reason>

agentshield runtime ingest <events.jsonl>
agentshield runtime trace <trace-id> --json
```

SQLite is opened read-only and requires a table name:

```bash
agentshield memory audit memory.db --table memories --content-column content
```

The default privacy mode is `pii-secrets`. Use `--privacy metadata-only` when no content excerpt may
appear in a report. Quarantine never deletes or rewrites the source. AgentShield places a local,
mode-0600 snapshot and append-only hash-chained audit log in `.agentshield/`; restore reverses the
quarantine state.

## Local API and dashboard

Start both processes in separate terminals:

```bash
corepack pnpm dev:api
corepack pnpm dev:dashboard
```

Open `http://127.0.0.1:4173`. The API binds to `127.0.0.1:4141` unless explicitly configured. It
accepts requests only from loopback browser origins, limits request bodies to 1 MiB, and stores
normalized reports under `.agentshield/`.

## Security model

- Static scans never import or execute target code.
- Symbolic links, oversized files, build output, and dependency directories are skipped.
- Parser failures create an explicit incomplete-analysis finding.
- Raw credentials are redacted before evidence or error serialization.
- Runtime payloads are hashed; sensitive metadata keys become hashes.
- Cloud upload, automatic hard deletion, LLM classification, and telemetry are disabled.

AgentShield cannot prove that a component is safe. Review declared behavior, dependency provenance,
and runtime approvals alongside its evidence. See [`SECURITY.md`](./SECURITY.md) for disclosure.

## Development

```bash
corepack pnpm typecheck
corepack pnpm test
corepack pnpm lint
corepack pnpm build
```

The code is Apache-2.0 licensed. Hosted multi-tenant features, SSO, billing, managed notification
integrations, and production infrastructure remain deployment work rather than being simulated in
the local Community edition.
