# Changelog

All notable changes follow Keep a Changelog and semantic versioning.

## [0.2.0] — 2026-08-09

### Added

- Agent persona system (`agentshield persona create|verify|render|apply|model|list|get`).
  Personas are declarative YAML definitions (role, goals, guardrails, system-prompt template,
  required/default variables) validated for shape, policy, and injection content before use.
- Model provider adapters via `buildModelRequest` for OpenAI Chat Completions, Anthropic Messages,
  Gemini, Mistral, Ollama, and the OpenAI Responses API, plus a generic pass-through provider.
  `persona model` renders a persona and emits a provider-native chat request.
- Hash-chained persona application receipts (`persona1:` … `personaN:`) that bind the persona
  definition, rendered system prompt, variable values, and the applying actor, with an immutable
  audit chain and context-scoped rollback.
- Loopback API endpoints for persona registration (YAML definition text), apply, model-request
  (provider/model validated before any receipt is recorded), listing, and application audit.
- Runtime SDK bridge `applyPersonaToModel` (`@agentshield/runtime`): applies a persona from the
  store, builds the provider-native model request, and records a `persona.applied` gate event with
  an evidence-graph edge; recording is an explicit `{ gate, context }` option. The `persona.applied`
  event type renders with its persona/version/digest metadata in the dashboard Runtime traces view.
- Dashboard Personas view: register, apply, build model requests, and browse the application audit
  chain with receipts.
- Jailbreak detection rules `AS-SC-028` (jailbreak activation frameworks, Athena/ColdBrew-style:
  activation banners, `[[AX:*]]` tokens, profile chains, `max-breaker`) and `AS-SC-029` (known
  jailbreak personas/modes: DAN, Developer Mode, STAN, AIM, DUDE, God Mode, plus multi-turn
  signatures such as Crescendo attacks, deceptive alignment, reward hacking, and sandbagging).
  Generic terms (developer mode, god mode) and jailbreak intent phrases only fire when co-occurring
  with activation artifacts to keep false positives low; findings are advisory and never auto-block.
- Jailbreak-related vulnerable corpus fixtures (`athena-jailbreak`, `jailbreak-prompt`), threat
  scenarios `T-15` and `T-16`, adversarial golden negatives, and a `jailbreak` badge on matching
  findings in the dashboard.
- Persona advisory injection scanner: warnings for jailbreak activation tokens, jailbreak
  personas, and multi-turn attack phrases (warning, not rejection). Safe persona fixture
  conformance test validating every `fixtures/safe/personas/*.yaml`.
- Decision record ADR-006 documenting the jailbreak detection policy (distinctive artifacts fire
  standalone; generic terms require co-occurrence; findings are advisory).

### Notes

- Only the persona and jailbreak-detection work since 0.1.0 is listed here; the remaining
  [Unreleased] items stay unreleased.

## [Unreleased]

### Added

- Framework-neutral parser intermediate representation.
- JavaScript/TypeScript AST parsing with same-file environment-to-network data-flow evidence.
- Structural TOML, JSONL, YAML, MCP tool, and Markdown parsing.
- Explicit conservative-analysis findings for Python and shell sources.
- Invisible Unicode control-character detection (`AS-SC-026`).
- Golden quality catalog with one positive and two safe negatives for all production rules.
- Reproducible 10,000-file scanner benchmark and filesystem discovery hardening.
- Baseline create, add, validate, and prune lifecycle with atomic persistence.
- Versioned policy v2 expressions, deterministic traces, and multi-report simulation.
- Versioned read-only memory adapter contract with pagination and conformance validation.
- Safe per-record incremental memory assessment cache with deterministic invalidation.
- In-memory ZIP package scanning with archive-bomb, traversal, depth, and entry-count limits.
- In-memory TAR, TAR.GZ/TGZ, and Python wheel scanning under the same limits as ZIP, including tar
  header checksum verification and rejection of archived hard links and symlinks.
- Component supply-chain provenance from `package.json` and `pyproject.toml` manifests, with resolved
  versions, integrity hashes, and registry URLs from npm and pnpm lockfiles.
- Unpinned and remote dependency specifier inventory per component.
- Deterministic seeded parser fuzzing across mutated corpus, degenerate, and oversized inputs.
- Memory detectors for hidden Unicode control characters (`AS-ME-012`) and base64/HTML-entity
  encoded hidden instructions (`AS-ME-013`), bringing stored-memory detection to parity with the
  scanner's `AS-SC-026`. The memory detector version bumped to `2026.08.2` to invalidate the
  per-record assessment cache.
- Multilingual (Indonesian and English) hidden-instruction threat fixtures `T-11` (hidden Unicode),
  `T-12` (encoded payload), `T-13` (hidden HTML instruction), and `T-14` (wildcard MCP scope).
- Structured memory rule catalog (`AS-ME-001`…`AS-ME-013`) exposed via `rules list` and `explain`, so
  memory detector rules are documented alongside `AS-SC-*`. The catalog is the single source of truth
  for memory rule metadata, guarded by a drift-prevention test.
- Memory audit SARIF 2.1, CycloneDX-compatible AgentBOM, and a self-contained evidence bundle export
  via `agentshield memory audit --format sarif|agentbom|bundle`. Memory evidence reports the record
  source URI with a redacted excerpt, and secret material is redacted across every export format.
- Local telemetry consent management (`agentshield telemetry status|enable|disable|preview`). Consent
  is off by default, recorded as a hash-chained receipt under `.agentshield/`, and the data preview
  documents exactly what a future opt-in could collect. Nothing is transmitted in the Community
  edition.
- Reusable composite GitHub Action (`.github/actions/scan`) plus GitLab, Azure Pipelines, and Jenkins
  CI examples under `docs/operations`. The action runs a static scan, writes SARIF, uploads it to
  GitHub code scanning, and fails the pipeline on a block or severity policy outcome.
- Shell completion scripts for bash, zsh, and fish (`agentshield completion <shell>`), a roff man page
  (`docs/operations/agentshield.1`), and install/upgrade/uninstall guidance
  (`docs/operations/install.md`).
- Persisted reversible memory remediation state machine (`agentshield remediation plan|approve|execute|rollback|reject|list|get`)
  with idempotency keys, optional two-person approval, and compare-and-swap source-hash guards. CLI
  exercises the full plan→approve→execute→rollback lifecycle without hard-deleting the source.
- TypeScript runtime SDK (`AgentShieldGate`) with synchronous `beforeTool`/`beforeMemoryWrite` policy
  gates, approval request/resolve, signed action receipts, fail-open/fail-closed modes, and a sanitized
  incident evidence graph. Runtime policy matching now scopes tool and memory patterns to the matching
  event kind so a tool policy no longer matches memory events.
- Loopback API endpoints for scan listing with cursor pagination, rule catalog lookup, memory audit
  listing, memory evidence-bundle export, the remediation plan→approve→execute→rollback lifecycle, and
  a stable error catalog (`/v1/errors`). Remediation conflicts return `409 remediation_conflict`.
- Dashboard Memory view (audit, trust dimensions, poisoning review queue, conflict explorer, evidence
  bundle export, plan quarantine), Runtime traces view (events + causal graph + evidence gaps), and a
  Policies view (evaluate a report against a YAML/JSON policy). Placeholder tabs are now interactive.
- Source-store inventory reconciliation (`memory reconcile`) and evidence-backed memory type
  classification (`memory classify`) with documented exclusions and derived-type evidence.
- VPS deployment stack: bearer-token API authentication (timing-safe, hashed), in-memory rate
  limiting (429 + `Retry-After`), configurable CORS origins, TLS support, `--generate-token` helper,
  production Dockerfile with healthcheck, Caddy image (builds + serves dashboard with auto-TLS),
  `docker-compose.vps.yml` (API internal + Caddy on 80/443), and a step-by-step deployment runbook
  with security checklist.
- Sharper memory detectors: `AS-ME-003` now reports conflicts only when the records' validity
  windows overlap; `AS-ME-005` applies a per-record freshness policy (explicit `ttl:<n>` labels,
  per-type defaults, grace period, volatility escalation for web/email/document sources) and
  suppresses the stale finding for facts superseded by a newer record of the same entity;
  `AS-ME-009` matches PII through `en-US`/`id-ID` locale packs plus configurable organization terms.
  The memory detector version bumped to `2026.08.3` to invalidate the per-record assessment cache.
- Generic read-only PostgreSQL memory adapter (`packages/memory/src/postgres.ts`). The adapter is
  driver-agnostic: every operation runs inside `BEGIN TRANSACTION READ ONLY` with a bounded
  `statement_timeout`, uses keyset pagination, infers content/id columns, and never exposes mutation
  methods, so the existing adapter conformance suite proves no write query can be issued in audit
  mode. The real node-postgres driver is lazy-imported (with actionable guidance when absent); the
  conformance tests use an in-memory driver that rejects non-SELECT statements.
- Signed rulepack package (`@agentshield/rulepack`) and CLI (`agentshield rulepack
  keygen|build|verify|install|list|rollback`). A rulepack bundle carries a deterministic ed25519
  signature over a canonical manifest and a SHA-256 binding of the serialized rules, so tampered
  signatures, tampered rules, and impostor publisher keys are all rejected before installation.
  `rulepack install` keeps a local update history under `.agentshield/rulepacks.json` and
  `rulepack rollback` restores the previous version; `scan --rulepack <bundle> --rulepack-key
  <public.pem>` runs the verified rule set instead of the built-in rulepack.
- MCP declaration-vs-implementation analysis (`AS-SC-027`). Structured MCP configs now normalize
  tool input schemas, `annotations` (`readOnlyHint`/`destructiveHint`), handler references, and
  declared server/tool permissions. When a tool declares read-only or narrowly scoped behavior but
  its referenced handler performs destructive operations (delete, write, process execution,
  messaging), the scanner reports `AS-SC-027` with evidence from both the declaration and the
  handler implementation.

### Changed

- Python is now parsed with a pure-TypeScript AST parser (indentation tokenizer, f-strings, imports,
  aliases, receiver chains) instead of conservative token analysis. It produces the same
  call/import/operation IR as JavaScript/TypeScript and provides intra-file secret-to-network data
  flow, so `AS-SC-001` reports `ast-data-flow` evidence for Python. Malformed Python degrades to the
  stable `PY_SYNTAX`/`AS-SC-900` path instead of a conservative warning.
- JavaScript/TypeScript permission mapping now consumes AST operations rather than text matches.
- `AS-SC-001` no longer fires on valid JS/TS unless a secret-derived value reaches a network call.
- Policy v1 remains supported while policy v2 adds typed nested expressions without dynamic evaluation.
- `Component` carries an optional `provenance` object; the addition is backward compatible and does
  not change `SCHEMA_VERSION`.

### Fixed

- Pathologically nested source no longer aborts a scan. `parseSource` now contains parser failure and
  stack exhaustion, emitting `PARSER_RESOURCE_EXHAUSTED` or `PARSER_FAILED` so the scanner reports an
  incomplete-analysis finding instead of a falsely clean result. Found by the new fuzz suite.
- A leading UTF-8 byte-order mark no longer breaks analysis. Previously a BOM made JSON manifests and
  lockfiles unparseable, degrading a scan to `partial` and losing provenance, and also raised a false
  high-severity `AS-SC-026` invisible-character finding. The mark is now neutralized without shifting
  reported line, column, or index values.

## [0.1.0] — 2026-08-03

### Added

- Local static scanner with 24 deterministic supply-chain rules and permission mapping.
- JSON, SARIF 2.1, self-contained HTML, and CycloneDX-compatible AgentBOM output.
- YAML policy evaluation, CI exit codes, baselines, rule explanation, and risk diffing.
- JSON, JSONL, Markdown, and read-only SQLite memory adapters.
- Deterministic freshness, duplicate, conflict, secret, PII, and poisoning detection.
- Reversible local quarantine, restore, and hash-chained remediation audit events.
- Sanitized runtime event ingestion and source-to-action evidence graphs.
- Loopback REST API, local dashboard, fixtures, documentation, and cross-platform CI.
