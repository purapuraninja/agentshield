# AgentShield

AgentShield is a local-first security scanner and memory hygiene toolkit for AI agents. It inspects
skills, MCP configuration, prompts, scripts, and stored memory without executing target code. Every
finding includes deterministic evidence and remediation.

This repository implements the local Community product described in
[`AGENTSHIELD_DEVELOPMENT_PLAN.md`](./AGENTSHIELD_DEVELOPMENT_PLAN.md): static scanning, permission
mapping, policy-as-code, JSON/SARIF/HTML/AgentBOM reports, read-only memory auditing, reversible
quarantine, sanitized runtime events, agent personas with provider-native model requests,
jailbreak/prompt-injection detection, a REST API, and a local dashboard.

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

Baseline suppressions are exact-fingerprint, owned, reasoned, and expire after at most 365 days.
Expired suppressions never hide findings. Writes use an atomic replacement to avoid a partially
written baseline.

Policy v2 supports typed predicates, nested `all`/`any`/`not` expressions, project/organization
scope metadata, deterministic evaluation traces, and simulation across multiple historical reports.
Policy v1 files remain supported for compatibility.

## CLI

```text
agentshield scan <file-or-directory>
agentshield scan-mcp <config>
agentshield permissions <target>
agentshield diff <old> <new>
agentshield policy check <report.json> <policy.yaml>
agentshield policy simulate <policy.yaml> <report.json...> [--json] [--fail-on-block]
agentshield report <report.json> --format html
agentshield rules list
agentshield explain AS-SC-001

agentshield baseline create <report.json> --owner <name> --reason <reason> --output baseline.json
agentshield baseline add <baseline.json> <report.json> --finding <sha256:fingerprint> --owner <name> --reason <reason>
agentshield baseline validate <baseline.json>
agentshield baseline prune <baseline.json>

agentshield rulepack keygen --dir <keys>
agentshield rulepack build <version> <publisher> --key <private.pem> --output bundle.json
agentshield rulepack verify <bundle.json> --key <public.pem>
agentshield rulepack install <bundle.json> --key <public.pem> --store .agentshield
agentshield rulepack list
agentshield rulepack rollback
agentshield scan <target> --rulepack <bundle.json> --rulepack-key <public.pem>

agentshield memory audit <json|jsonl|markdown|sqlite>
agentshield memory quarantine <target> <memory-id> --actor <name> --reason <reason>
agentshield memory restore <target> <memory-id> --actor <name> --reason <reason>
agentshield memory reconcile <target>

agentshield remediation plan <target> <memory-id> <quarantine|restore|deprecate> --actor <name> --reason <reason>
agentshield remediation approve|execute|rollback <target> <plan-id> --actor <name>

agentshield persona create <file.yaml> --actor <name>
agentshield persona list|show <id>|render <id>|verify <file>|applications|remove <id>
agentshield persona apply <id> --actor <name> [--set name=value]
agentshield persona model <id> --provider <provider> --model <name> --actor <name>

agentshield runtime ingest <events.jsonl>
agentshield runtime trace <trace-id> --json

agentshield telemetry status|enable|disable|preview
```

SQLite is opened read-only and requires a table name:

```bash
agentshield memory audit memory.db --table memories --content-column content
```

The default privacy mode is `pii-secrets`. Use `--privacy metadata-only` when no content excerpt may
appear in a report. Quarantine never deletes or rewrites the source. AgentShield places a local,
mode-0600 snapshot and append-only hash-chained audit log in `.agentshield/`; restore reverses the
quarantine state.

Memory inventory runs through a versioned, paginated, read-only adapter contract. Per-record detector
results are cached in `.agentshield/memory-cache.json`; the cache key includes adapter, external ID,
content and record fingerprints, detector version, privacy mode, and a daily freshness bucket. Use
`--no-cache` to force reassessment or `--page-size <1..5000>` to tune inventory pages. Relational
duplicate/conflict checks are always recomputed over the complete current inventory. Conflicts are
reported only when validity windows overlap; staleness follows a per-record policy (explicit
`ttl:<n>` labels, per-type defaults, volatility escalation for web/email/document sources, and
supersession by newer facts); and PII matches `en-US`/`id-ID` locale packs plus configurable
organization terms.

## Agent personas

Personas are trusted, versioned system-prompt templates with declared variables. Registering
validates structure; applying renders the prompt and records an immutable, hash-chained receipt in
`.agentshield/persona-applications.jsonl` (the raw prompt is never stored — only its hash). The
injection scanner is advisory: operator-owned personas are never rejected for their content, only
for structural problems (schema violations, undeclared variables, missing required variables).

```bash
agentshield persona create fixtures/safe/personas/code-reviewer.yaml --actor platform-team
agentshield persona verify fixtures/safe/personas/security-analyst.yaml
agentshield persona apply code-reviewer --actor deploy-bot --set focus=secrets
agentshield persona applications
```

Assign a persona to an AI model — applies the persona (recording a receipt) and emits a
provider-native request as JSON. No network call is made:

```bash
agentshield persona model code-reviewer --provider openai --model gpt-4o --actor deploy-bot --set focus=secrets --max-tokens 512
```

Supported providers: `openai` (chat completions), `anthropic`, `gemini`, `mistral`, `ollama`,
`responses` (OpenAI Responses API), and `generic`.

In an agent harness, one call applies the persona, builds the model request, and records the
application as a sanitized `persona.applied` runtime event (prompt digest + receipt only) so it
appears in the evidence graph:

```ts
import { AgentShieldGate, applyPersonaToModel } from '@agentshield/runtime';

const gate = new AgentShieldGate({ policies });
const { request, gateReceipt, event } = await applyPersonaToModel(
  '.', 'code-reviewer',
  { actor: 'deploy-bot', provider: 'openai', model: 'gpt-4o', variables: { focus: 'secrets' } },
  { gate, context: { traceId: 'run-42', actor: 'deploy-bot' } }
);
```

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

- JavaScript/TypeScript and Python use AST analysis; JSON/JSONL/YAML/TOML/Markdown use structural
  parsers. The Python parser is pure TypeScript: it tokenizes indentation-based blocks and f-strings
  and produces the same call/import/operation/data-flow IR as the JS/TS path.
- Static scans never import or execute target code.
- Direct `.zip`, `.whl`, `.tar`, and `.tar.gz`/`.tgz` targets are decoded in memory with file-count,
  expanded-size, compression-ratio, path-depth, entry-size, absolute-path, and traversal limits;
  entries are never extracted to disk. Tar headers are checksum-verified, and archived hard links and
  symlinks are rejected.
- Symbolic links, oversized files, build output, and dependency directories are skipped.
- Parser failures, including stack exhaustion on pathologically nested input, are contained and create
  an explicit incomplete-analysis finding rather than a falsely clean result.
- Conservative shell/PowerShell analysis creates an explicit analysis-gap finding instead of
  silently claiming AST coverage.
- Raw credentials are redacted before evidence or error serialization.
- Runtime payloads are hashed; sensitive metadata keys become hashes.
- Rulepacks are signed bundles: a deterministic manifest (publisher, version, rule digest) is signed
  with ed25519, and the rules are bound to the manifest by SHA-256. `rulepack install` refuses a
  bundle that fails signature or digest verification, and `rulepack rollback` restores the previous
  installed version from local state. Scanner rules only change through a verified rulepack.
- Jailbreak and persona-switching content is detected deterministically: framework artifacts such
  as Athena/ColdBrew-style activation tokens (`AS-SC-028`) and known jailbreak personas — DAN,
  Developer Mode, STAN, AIM, DUDE, plus multi-turn attack signatures (Crescendo, deceptive
  alignment, reward hacking, sandbagging evals) — (`AS-SC-029`). Distinctive artifacts fire
  standalone; generic or polysemous terms ("developer mode", "god mode", research terms) only
  fire when they co-occur with jailbreak intent, so security-education and tooling documentation
  do not produce findings. The same patterns are advisory warnings in persona templates; findings
  never auto-block or mutate content.
- Persona application receipts are hash-chained; a prompt digest (never the raw prompt) is all that
  can be recorded as a `persona.applied` runtime event.
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
