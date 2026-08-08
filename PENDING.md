# AgentShield — Pending Implementation

Dokumen ini adalah gap analysis antara `AGENTSHIELD_DEVELOPMENT_PLAN.md` dan implementasi lokal
v0.1.0 saat ini. Tujuannya adalah menjelaskan apa yang belum selesai, mengapa belum dianggap
production-ready, serta urutan implementasi yang aman.

Terakhir diperbarui: 2026-08-08.

## Arti status

- `[ ]` belum diimplementasikan.
- `[~]` sudah ada implementasi dasar, tetapi belum memenuhi acceptance criteria rencana utama.
- `[x]` sudah tersedia di v0.1.0 dan tidak dibahas kembali kecuali masih mempunyai gap.

## Baseline yang sudah tersedia

- [x] CLI lokal, schema Zod, static scanner, permission map, dan 25 deterministic supply-chain
  rules.
- [x] Parser IR, AST JavaScript/TypeScript, serta parsing struktural JSON/JSONL/YAML/TOML/Markdown.
- [x] Laporan JSON, SARIF, HTML, serta CycloneDX-compatible AgentBOM.
- [x] YAML policy evaluation, baseline consumption, diff, CI exit code, rule list, dan explain.
- [x] Audit read-only untuk JSON, JSONL, Markdown, serta SQLite.
- [x] Deteksi dasar untuk stale/expired memory, exact/near duplicate, konflik EAV sederhana, secret,
  PII, dan instruction-like poisoning.
- [x] Quarantine/restore lokal berbasis sidecar dengan snapshot dan hash-chained audit log.
- [x] Sanitized runtime event store dan evidence graph lokal.
- [x] Loopback REST API dan dashboard lokal untuk overview, scan, findings, serta permissions.
- [x] Lint, typecheck, 46 automated tests, cross-platform CI skeleton, Docker API, dan fixtures dasar.

## Ringkasan prioritas

| Prioritas | Outcome | Blok utama |
|---|---|---|
| P0 | Technical Preview yang dapat dipercaya | Parser AST, golden corpus lengkap, scanner hardening, benchmark |
| P0 | MVP Beta memory yang dapat diaudit | Adapter contract, incremental audit, PostgreSQL, detector quality |
| P1 | Remediation yang benar-benar memengaruhi retrieval | Version service, connector write hooks, approval, reindex, rollback drill |
| P1 | Runtime protection | SDK resmi, framework adapters, synchronous policy gate, signed receipt |
| P1 | Team product | PostgreSQL/Redis worker, auth/RBAC, tenant isolation, dashboard lengkap |
| P2 | GA | Fuzzing, signing, SBOM/provenance, load/DR testing, pentest, release automation |
| P3 | Enterprise | SSO/SCIM, SIEM/SOAR, air-gapped updates, data residency, billing |

---

## 1. Static scanner dan parser — P0

### Yang masih parsial

- [x] JavaScript/TypeScript sudah memakai AST dan common intermediate representation untuk imports,
  calls, operations, permissions, serta intra-file data flow.
- [x] Python memakai AST parser murni TypeScript (tokenizer indentation + f-string, parser recursive
  descent) yang menghasilkan IR dan intra-file data flow yang sama dengan JS/TS; shell dan
  PowerShell masih conservative.
- [x] JSON, JSONL, YAML, dan TOML sudah diparse secara struktural dengan diagnostics.
- [x] Markdown sudah memparse front matter, link, command, code block, hidden HTML instruction, dan
  invisible Unicode.
- [x] Rule `AS-SC-001` membuktikan intra-file identifier flow untuk JavaScript/TypeScript dan Python
  (`os.getenv`/`os.environ` → `requests`/`urllib`/f-string), termasuk alias import dan receiver
  chain; shell masih memakai taint-lite fallback dan inter-file flow belum tersedia.
- [x] MCP tool mismatch sudah membandingkan tool schema, `annotations` (read-only/destructive hint),
  declared permissions, dan implementasi handler (`AS-SC-027`). Tool yang mendeklarasikan read-only
  tetapi handler-nya melakukan operasi destruktif dilaporkan dengan evidence dari kedua file.
- [~] Discovery sudah menghormati `.gitignore`/`.agentshieldignore`, direct archive target, serta
  package metadata dan lockfile provenance (`package.json`, `pyproject.toml`, npm/pnpm lockfile);
  Git ref, container digest, dan signature verification belum tersedia.
- [x] Direct `.zip`, `.whl`, `.tar`, dan `.tar.gz`/`.tgz` dipindai in-memory dengan proteksi archive
  bomb, path traversal, tar checksum, serta penolakan hard link/symlink. Nested archive belum dibuka.
- [x] Rulepack manifest bertanda tangan ed25519, updater lokal, rollback rulepack, dan verifikasi
  publisher (`agentshield rulepack keygen|build|verify|install|list|rollback`, package
  `@agentshield/rulepack`). Signature mengikat manifest canonical, digest SHA-256 mengikat rules,
  dan `scan --rulepack --rulepack-key` menjalankan rule set terverifikasi.
- [ ] Optional sandboxed dynamic analysis.

### Cara mengimplementasikan

1. [x] Tambahkan package `packages/parsers` dan common intermediate representation:
   `FileNode`, `CallNode`, `DataSource`, `DataSink`, `ToolDefinition`, serta `ParseDiagnostic`.
2. [x] Gunakan TypeScript Compiler API untuk JS/TS, parser Python murni TypeScript di
   `packages/parsers/src/python.ts` (tanpa runtime Python eksternal, konsisten dengan ADR-001),
   parser shell yang tidak mengeksekusi input, `remark` untuk Markdown, serta parser JSON/YAML/TOML
   yang strict.
3. [~] Ubah rule engine agar rule menerima IR, bukan raw text. Permission mapping dan rules tertentu
   sudah memakai IR; regex tetap dipakai sebagai conservative
   fallback dan setiap fallback harus menurunkan confidence atau menghasilkan analysis gap.
4. [x] Bangun intra-file data flow untuk source `process.env`/`os.getenv`/`os.environ`, credential
   files, dan secret manager output menuju sink `fetch`, HTTP clients, messaging, logs, atau child
   process, untuk JavaScript/TypeScript dan Python.
5. [x] Untuk MCP, normalkan server, tools, input schema, annotations, declared side effects, dan handler
   references. Bandingkan destructive implementation dengan description/approval declaration.
6. [~] Package name, declared/resolved version, repository URL, lockfile resolution, integrity hash,
   serta unpinned/remote dependency sudah masuk `Component.provenance`. Container digest dan signature
   status belum tersedia.
7. [x] ZIP, wheel, tar, dan tar.gz diproses sebagai virtual files tanpa ekstraksi dengan batas jumlah
   file, total expanded size, compression ratio, depth, entry size, absolute path, dan traversal.

### Acceptance criteria

- [x] Parser tidak pernah mengeksekusi target.
- [x] Semua parse failure menjadi `AS-SC-900` dengan format, file, dan alasan yang stabil.
- [x] Critical fixture recall 100% untuk skenario deterministic yang didefinisikan.
- [x] High-severity false-positive rate di bawah 10% pada maintained safe golden corpus.
- [~] Reproducible gate 10.000 file/5 menit tersedia melalui `pnpm benchmark:scanner` dan lulus pada
  environment development; release evidence dari mesin referensi 4-vCPU masih diperlukan.
- [x] Archive bomb, path traversal, symlink escape, tar checksum/size corruption, duplicate entry, dan
  file lebih besar dari limit telah mempunyai regression test untuk ZIP, wheel, tar, dan tar.gz.

## 2. Rule quality, fixtures, dan benchmark — P0

- [x] Golden regression tests tersedia untuk seluruh production static rules.
- [x] Minimal satu true-positive dan dua safe negative fixture per production rule.
- [ ] Corpus minimal 30 extension publik dan 15 intentionally vulnerable fixtures untuk T-01–T-10.
- [~] Corpus multilingual, khususnya instruksi Indonesia dan Inggris. Skenario T-04, T-11, T-12,
  T-13, dan T-14 sudah mencakup instruksi Indonesia dan Inggris; korpus 30 ekstensi publik dan 15
  intentionally vulnerable fixture masih diperlukan.
- [~] Fixture precision, recall, confusion matrix, dan hasil per rule tersedia; public-corpus metrics,
  suppression rate, dan real-world false-positive rate belum tersedia.
- [~] Rule owner, last review date, dan stale-review quality gate tersedia; approval workflow belum ada.
- [~] Deterministic seeded mutation/fuzz tests untuk parser tersedia (`packages/parsers/src/fuzz.test.ts`)
  dan sudah menemukan satu parser crash nyata; fuzzing untuk malformed memory record dan runtime event
  schema belum ada.

### Cara mengimplementasikan

1. Buat `fixtures/rules/<rule-id>/{positive,negative}/` dan metadata expected result dalam JSON.
2. Buat fixture runner yang memindai seluruh corpus dan membandingkan rule ID, severity, confidence,
   normalized evidence, serta remediation.
3. [x] Tambahkan benchmark dengan fixture generator configurable hingga 10k file dan budget gate.
4. Tambahkan job terjadwal untuk fuzzing dan benchmark; jangan menjalankan malicious fixture di host
   production.
5. Publikasikan metrik kualitas rule di generated documentation.

## 3. CLI, reports, policy, dan distribution — P0/P1

- [x] Baseline mempunyai command create/add/validate/prune, atomic persistence, duplicate detection,
  serta active/expired status.
- [~] Policy v2 mendukung typed predicates, nested boolean expression, scope metadata,
  deterministic trace, dan multi-report simulator; persisted version history serta exception
  approval belum ada.
- [x] Signed rulepack update command dan offline rulepack bundle (`rulepack build/install/rollback`
  dan file bundle `.rulepack.json` tunggal).
- [x] Telemetry opt-in command, consent receipt, dan data preview (`agentshield telemetry
  status|enable|disable|preview`). Default tetap off dan tidak ada transmisi di edisi Community.
- [ ] npm release pipeline, changelog automation, artifact signing, checksum, SBOM, dan provenance
  attestation.
- [x] Shell completions, man page, upgrade/uninstall documentation (`agentshield completion`,
  `docs/operations/agentshield.1`, `docs/operations/install.md`).
- [x] Memory SARIF/AgentBOM export dan evidence bundle export (`memory audit --format
  sarif|agentbom|bundle`).
- [x] GitHub Action reusable resmi serta generic CI examples untuk GitLab/Azure/Jenkins
  (`.github/actions/scan` dan `docs/operations/ci-*`).

### Cara mengimplementasikan

1. [x] Tambahkan `baseline create`, `baseline add`, `baseline prune`, dan `baseline validate`. Setiap entry
   wajib mempunyai owner, reason, finding fingerprint, dan expiry.
2. [x] Definisikan policy schema versioned dengan `all`, `any`, `not`, typed operands, dan deterministic
   evaluation trace. Jangan memakai `eval`.
3. Simpan policy versions immutable; publish policy baru melalui simulation terhadap historical
   reports sebelum aktivasi.
4. Buat release workflow yang menjalankan test, pack smoke test, menghasilkan CycloneDX SBOM,
   menandatangani tarball/checksum, lalu mempublikasikan hanya dari protected tag.

## 4. Memory adapters dan inventory — P0

- [x] JSON/JSONL/Markdown/SQLite memakai kontrak adapter versioned dengan capability declaration,
  pagination, checkpoint, connection test, dan read-only audit surface.
- [x] Per-record incremental cache memakai adapter ID, external ID, content/record fingerprint,
  detector version, privacy mode, serta freshness bucket; detector relasional tetap dihitung ulang.
- [x] Generic PostgreSQL read-only adapter (`packages/memory/src/postgres.ts`): keyset pagination,
  `BEGIN TRANSACTION READ ONLY` + `statement_timeout` di setiap operasi, inferensi kolom, driver
  `pg` lazy-import opsional, dan conformance suite dengan in-memory driver yang menolak statement
  write.
- [ ] Satu vector database adapter pertama; keputusan produk masih diperlukan.
- [~] Pagination, checkpoint, dan JSONL per-record failure isolation sudah formal; retry serta rate
  limit untuk connector eksternal belum ada.
- [~] Source-store total reconciliation dan documented exclusions (`memory reconcile` / `POST
  /v1/memory/reconcile`); connection credential guidance serta automated least-privilege validation
  belum ada.
- [x] Memory type classification yang evidence-backed (`memory classify` / `POST /v1/memory/classify`).

### Cara mengimplementasikan

1. [x] Definisikan `MemoryAdapter` dengan method `testConnection`, `capabilities`, `inventoryPage`,
   `checkpoint`, `planMutation`, `applyMutation`, dan `restoreSnapshot`.
2. [x] Buat conformance suite yang wajib dilewati setiap adapter, termasuk proof bahwa audit mode tidak
   dapat memanggil write method.
3. [x] Simpan cache berdasarkan adapter ID, external ID, content hash, detector version, dan privacy mode.
   Reuse assessment hanya jika semua key cocok.
4. Gunakan role database read-only, transaction read-only, query timeout, page size, dan maximum
   record size.
5. Pilih vector database berdasarkan design partner; kandidat awal: pgvector bila ingin mengurangi
   jumlah infrastruktur, atau Qdrant bila standalone vector workflow menjadi prioritas.

### Acceptance criteria

- [ ] Repeated scan hanya menghitung ulang record yang berubah.
- [ ] Satu record rusak tidak menggagalkan seluruh audit.
- [ ] Inventory totals cocok dengan source store dalam documented exclusions.
- [x] Tidak ada write query yang dapat dijalankan saat audit mode (conformance suite membuktikan
  adapter audit tidak mengekspos mutation method dan driver menolak statement non-SELECT).
- [ ] Raw memory tidak masuk log atau cloud event secara default.

## 5. Memory intelligence — P0/P1

- [~] Near duplicate masih memakai token Jaccard, bukan embedding atau semantic similarity.
- [x] Conflict detection membandingkan nilai per entity/attribute dan hanya menandai conflict bila
  validity windows overlap (`AS-ME-003`); fakta yang tidak overlap tidak lagi salah dilaporkan.
- [x] Freshness memakai policy per record: label `ttl:<n>` eksplisit, default per memory type
  (working/episodic/semantic/procedural), grace period, dan eskalasi severity untuk source volatile
  (web/email/dokumen). Fakta yang sudah disupersede oleh fakta lebih baru untuk entity yang sama
  tidak lagi dilaporkan stale (`AS-ME-005`). Source modified time tetap belum dipakai.
- [x] PII detector memakai locale packs `en-US` dan `id-ID` (SSN, NIK, NPWP, kartu, telepon) serta
  organization terms yang bisa dikonfigurasi via `AuditOptions.organizationTerms` (`AS-ME-009`).
- [~] Poison detector kini mendeteksi hidden Unicode (`AS-ME-012`) dan instruksi tersembunyi dalam
  encoding base64/HTML entity (`AS-ME-013`), sejajar dengan `AS-SC-026`; policy conflict, provenance
  mismatch, dan indirect tool instruction secara menyeluruh belum tersedia.
- [ ] Corroboration dari beberapa independent sources.
- [ ] Optional LLM classifier dengan cited memory IDs, pinned evals, local-model option, dan label
  yang membedakan hasil model dari deterministic findings.
- [ ] Conflict explorer API/UI.

### Cara mengimplementasikan

1. Tambahkan detector interface versioned dan simpan detector version di assessment.
2. Gunakan local embedding model atau configured embedding provider hanya setelah redaction/consent;
   simpan vector secara lokal dan gunakan threshold yang dikalibrasi dari corpus.
3. [x] Ekstrak EAV + temporal qualifier, kelompokkan per normalized entity/attribute, lalu pilih conflict
   hanya jika value berbeda dan validity windows overlap.
4. [x] Buat freshness policy per label/type: volatility, default TTL, grace period, authoritative source,
   serta review cadence.
5. [~] Tambahkan Unicode normalization, zero-width character detection, base64/HTML-hidden instruction
   analysis, dan policy-versus-memory comparison.
6. LLM output hanya boleh menambah `assisted` finding; tidak boleh sendiri memblokir, menghapus, atau
   menulis ulang memory.

## 6. Remediation, versioning, dan rollback — P1

- [~] Quarantine sidecar melindungi audit AgentShield berikutnya, tetapi belum menghentikan retrieval
  oleh framework/agent di luar AgentShield.
- [x] State machine persisted `planned -> approved -> executed -> rolled_back` (dan `rejected`) sebagai
  schema `remediation.json`, dipisahkan menjadi `plan`, `approve`, `execute`, `rollback`, dan `reject`.
  Setiap tahap menyimpan actor, reason, timestamp, dan source hash.
- [x] Idempotency key pada planning (re-planning dengan key yang sama mengembalikan plan yang ada).
- [x] Two-person approval opsional (`requireTwoPerson` menolak approver yang sama dengan planner).
- [x] Compare-and-swap: eksekusi membandingkan source hash saat ini dengan hash saat planning dan
  membatalkan operasi bila berubah.
- [~] Snapshot lokal tersedia, tetapi belum ada backup verification terenkripsi, retention, atau
  snapshot garbage collection.
- [ ] Connector write hooks untuk record-level quarantine/deprecation/TTL.
- [ ] Dry-run diff yang spesifik untuk source store.
- [ ] Immutable memory version service.
- [ ] Atomic batch mutation, partial-failure recovery.
- [ ] Vector reindex dan source/index consistency verification.
- [ ] Hard-delete-after-retention workflow; harus tetap disabled by default.

### Cara mengimplementasikan

1. Implementasikan state machine `active -> review_required -> quarantined -> restored` dan jalur
   `deprecated -> deleted_after_retention` sebagai schema persisted, bukan hanya sidecar status.
2. Pisahkan `plan`, `approve`, `execute`, dan `rollback`. Setiap tahap menyimpan actor, reason,
   timestamp, source hash, adapter version, dan idempotency key.
3. Sebelum mutation, buat snapshot terenkripsi dan lakukan read-back verification. Batalkan operasi
   bila backup verification gagal.
4. Adapter menerapkan compare-and-swap dengan expected source hash agar perubahan eksternal tidak
   tertimpa.
5. Setelah perubahan vector source, lakukan reindex lalu verifikasi record/index counts dan hashes.
6. Tambahkan integration rollback drill untuk setiap write-capable adapter sebelum feature flag write
   dapat diaktifkan.

## 7. Runtime SDK, policy gate, dan correlation — P1

- [~] Ada event schema/store dan evidence graph lokal, tetapi belum menjadi SDK versioned yang
  dipublikasikan.
- [~] Runtime policy evaluator ada sebagai helper, belum mengintersep tindakan agent secara sinkron.
- [ ] TypeScript runtime SDK public dan Python SDK.
- [ ] Adapter untuk dua framework agent pertama.
- [ ] Proxy/collector dengan batching, retry, backpressure, offline buffering, dan deduplication.
- [ ] Pre-tool dan pre-memory-write policy gate.
- [ ] Approval request/resolve workflow.
- [ ] Per-action fail-open/fail-closed configuration.
- [ ] Signed action receipts dan sanitized incident evidence export.
- [ ] Evidence graph persistence/query yang dapat diskalakan.
- [ ] Incident replay dengan sanitized events.

### Cara mengimplementasikan

1. Pisahkan package `runtime-sdk` dari collector dan publikasikan stable event schema fixtures.
2. Sediakan middleware `beforeTool`, `afterTool`, `beforeMemoryWrite`, `afterMemoryWrite`, serta
   retrieval hooks; setiap hook membawa trace/parent/causality IDs.
3. Gate mengirim context yang sudah disanitasi ke policy engine dan mengembalikan allow, warn,
   require approval, quarantine, atau block dalam latency budget.
4. Simpan outbox lokal dengan monotonically increasing sequence dan event ID; ack hanya setelah
   collector melakukan durable persistence.
5. Tanda tangani decision receipt yang mengikat policy version, input hash, result, timestamp, dan
   actor/component identity.

## 8. API, persistence, worker, dan reliability — P1

- [~] API berjalan sinkron dan menyimpan JSON/JSONL lokal; belum memakai database, migration, queue,
  atau object storage.
- [~] Event ID idempotent secara sequential, tetapi belum aman terhadap concurrent writers.
- [ ] PostgreSQL schema/migrations untuk organization, project, agent, scan, finding, memory,
  remediation, runtime event, policy, decision, dan audit event.
- [ ] Redis/BullMQ worker untuk scan, report, reindex, notifications, dan retention jobs.
- [ ] S3-compatible artifact store untuk report/evidence bundle.
- [~] Missing draft endpoints: scan cancel, global components/permissions masih belum ada; remediation
  approve, execute, rollback, evidence export, dan cursor pagination sudah tersedia.
- [x] Idempotency keys pada remediation planning endpoint.
- [x] Cursor pagination, rate limiting, stable error catalog (`/v1/errors`), dan TLS support sudah
  tersedia; request schema/OpenAPI, timeouts, dan cancellation belum ada.
- [~] Structured logging (Fastify logger) dan readiness/liveness (`/health` + Docker healthcheck)
  sudah ada; metrics, OpenTelemetry traces, dan queue health belum ada.
- [ ] Backup, point-in-time recovery, migration rollback, dan disaster-recovery drill.

### Cara mengimplementasikan

1. Buat migration pertama dan repository interfaces; local filesystem tetap menjadi backend
   Community, PostgreSQL menjadi backend server.
2. Endpoint `POST /v1/scans` hanya membuat job dan mengembalikan `202`; worker memperbarui status
   `queued/running/completed/partial/failed/cancelled`.
3. Terapkan unique constraint untuk tenant + idempotency key serta event ID. Gunakan transaction untuk
   mutation dan append audit event.
4. Generate OpenAPI dari route schemas dan jalankan contract tests terhadap SDK fixtures.
5. Tambahkan per-tenant quota/rate limit sebelum service dapat dibind ke non-loopback interface.

## 9. Authentication, authorization, dan tenancy — P1/P2

- [ ] User authentication, recent-auth requirement, session management, dan passwordless/OIDC login.
- [ ] Organization/project membership dan roles: Viewer, Analyst, Approver, Policy Admin, Org Admin.
- [ ] Scoped API tokens, hashing, rotation, expiry, dan revocation.
- [ ] Tenant row-level isolation untuk seluruh endpoint dan worker job.
- [ ] Audit log untuk setiap sensitive read/mutation.
- [ ] SSO/SAML dan SCIM.
- [ ] Data retention, export, deletion, dan tenant offboarding.

### Syarat sebelum API non-loopback

Jangan mengekspos API ke jaringan bersama hanya dengan mengganti `AGENTSHIELD_HOST`. Sebelum itu,
wajib ada TLS, authentication, authorization, tenant isolation, rate limiting, secret manager,
database encryption, backup/restore, dan security review. Docker example saat ini hanya cocok untuk
evaluasi lokal.

## 10. Dashboard dan product UX — P1

- [~] Overview, scan form, findings, permission map, filtering, dan API connectivity tersedia.
- [ ] Projects/agents/scans history dan trend data.
- [ ] Finding assignment, comments, lifecycle, exception, dan reviewer workflow.
- [~] Memory inventory/health view, conflict explorer, dan poisoning review queue sudah tersedia di
  dashboard; quarantine plan center masih CLI/API only (approval/execution/restore UI belum ada).
- [~] Runtime trace graph explorer dengan evidence-gap visualization sudah tersedia di dashboard.
- [~] Policy validator/simulator sudah tersedia di dashboard (evaluate report vs policy); editor,
  version history, publish, dan rollback belum ada.
- [ ] Users, roles, API tokens, integrations, retention, usage, dan billing screens.
- [ ] Accessible data tables, keyboard flow, responsive QA, screen-reader labels, dan WCAG 2.2 AA
  audit.
- [ ] Browser E2E tests untuk seluruh critical workflow.

### Cara mengimplementasikan

1. Buat typed API client dari OpenAPI dan query cache; jangan duplikasi schema server di UI.
2. Implementasikan route-based screens dan loading/error/empty/partial states untuk setiap resource.
3. Untuk evidence graph gunakan layout yang dapat menampilkan gap sebagai node eksplisit; jangan
   menghubungkan causal edge yang tidak direkam.
4. Sensitive memory content harus hidden secara default dan memerlukan project configuration + role +
   recent authentication untuk ditampilkan.
5. Tambahkan Playwright E2E untuk scan, triage, policy simulation, quarantine approval, rollback, dan
   trace exploration.

## 11. Deployment dan operations — P1/P2

- [~] Ada API Dockerfile (non-root, read-only, healthcheck) dan local Compose, serta VPS Compose
  dengan Caddy (auto-TLS + dashboard serving + API proxy); belum ada worker image, PostgreSQL,
  Redis, object storage, migrations, atau health-based orchestration.
- [~] Production Dockerfile dengan non-root user, read-only filesystem, dan no-new-privileges sudah
  ada; pinned digest dan image signing belum ada.
- [ ] Compose development stack lengkap.
- [ ] Kubernetes manifests/Helm chart, secrets integration, network policies, pod security, resource
  limits, autoscaling, dan disruption budgets.
- [ ] Ephemeral PR, staging, production, serta isolated security-test environments.
- [ ] SLO/alerts/status page dan runbooks untuk queue, DB, rulepack, credential, tenant incident, dan
  faulty remediation.
- [ ] Load test minimal 1.000 events/detik per tenant burst.

## 12. Security and privacy hardening — P0 sampai GA

- [ ] Signed CLI releases, containers, rulepacks, adapters, and provenance attestations.
- [ ] Dependency, secret, license, SAST, container, dan IaC scanning yang memblokir critical issues.
- [ ] SBOM untuk setiap release artifact.
- [ ] Fuzzing parser, malformed memory, Unicode, oversized input, dan event schema.
- [ ] Archive bomb, symlink, path traversal, decompression ratio, resource exhaustion, dan Windows path
  edge-case tests.
- [ ] Log/crash-dump secret leakage tests di seluruh service.
- [ ] Cryptographic design review untuk audit checkpoints dan signed receipts.
- [ ] Independent threat-model review dan external penetration test.
- [ ] Vulnerability disclosure workflow, CVE process, patch SLA, dan release revocation.
- [ ] Privacy policy, telemetry specification, data-flow inventory, dan deletion/export evidence.

## 13. Testing gaps — P0 sampai GA

- [~] Ada unit/fixture/API contract tests dasar; coverage belum diukur sebagai release gate.
- [ ] Tests untuk setiap rule, parser, policy expression, schema compatibility, dan redaction format.
- [ ] SQLite/PostgreSQL/vector adapter conformance and failure tests.
- [ ] Concurrent event idempotency and hash-chain tampering tests.
- [ ] Atomic remediation, partial failure, backup failure, reindex failure, dan rollback drills.
- [ ] API authentication, authorization, tenant isolation, pagination, limits, dan malformed requests.
- [ ] Dashboard Playwright accessibility/responsive tests.
- [ ] Performance, soak, load, queue backpressure, migration, backup, dan disaster recovery tests.
- [ ] Linux/macOS/Windows installation and upgrade tests dari oldest supported version.

## 14. Product dan external dependencies

Item berikut tidak dapat diselesaikan hanya dengan menulis kode; perlu keputusan atau bukti eksternal:

- [ ] Validasi nama/trademark dan domain AgentShield.
- [ ] Pilih vector database pertama.
- [ ] Tentukan batas Community/Pro/Team/Enterprise secara legal dan teknis.
- [ ] Tentukan repository organization, package scope, signing identity, dan release channel.
- [ ] Lakukan 8–12 user interviews dan kumpulkan minimal 30-extension corpus.
- [ ] Rekrut minimal tiga design partners dan validasi weekly usage/value metrics.
- [ ] Tentukan telemetry consent, retention, privacy policy, dan data processing terms.
- [ ] Tetapkan cloud provider, regions, RPO/RTO, incident ownership, dan operations budget.
- [ ] Paid beta hanya setelah tenant-isolation review dan data export/deletion workflow lulus.

---

## Urutan implementasi yang direkomendasikan

### Milestone A — Technical Preview hardened

1. Parser IR dan AST untuk JS/TS/Python/Markdown/config/shell.
2. Golden fixture matrix untuk semua rules.
3. Scanner benchmark dan filesystem/archive hardening.
4. Baseline management, signed rulepack format, dan release artifact signing.
5. Schema compatibility tests dan generated rule documentation.

**Gate:** critical fixture recall 100%, high false-positive <10%, tidak ada parser crash, install/scan
lulus di tiga OS.

### Milestone B — Complete memory MVP

1. Adapter SDK dan conformance suite.
2. Incremental checkpoint/cache.
3. PostgreSQL adapter dan satu vector adapter.
4. Semantic duplicate/conflict, richer freshness, poisoning, dan privacy detectors.
5. Memory report UI dan evidence export.

**Gate:** source totals reconcile, changed-record-only reprocessing, critical poisoned fixtures 100%,
raw memory tidak masuk log/cloud event.

### Milestone C — Safe remediation

1. Persisted remediation state machine dan immutable versions.
2. Plan/approve/execute/rollback API.
3. Backup verification dan compare-and-swap.
4. Write hooks per adapter, reindex, dan consistency check.
5. Two-person approval dan integration rollback drills.

**Gate:** tidak ada hard delete default, rollback mengembalikan source + index, backup failure selalu
mencegah mutation.

### Milestone D — Runtime differentiation

1. TypeScript/Python SDKs dan dua framework adapters.
2. Durable collector/outbox dan idempotent event persistence.
3. Synchronous policy gate dan approvals.
4. Signed receipts, evidence graph persistence, dan trace UI.
5. Latency/load tests serta fail-open/fail-closed policy.

**Gate:** test incident dapat direkonstruksi end-to-end; telemetry yang hilang tampil sebagai gap;
payload sensitif tidak tersimpan.

### Milestone E — Team beta dan GA

1. PostgreSQL/Redis/object storage architecture dan async workers.
2. Auth, RBAC, API tokens, tenant isolation, retention/export/delete.
3. Dashboard team workflows dan notifications.
4. Production deployment, observability, backups, DR, rate limits, dan SLO.
5. Fuzzing, signing, SBOM, pentest, accessibility, documentation, dan public beta.

**Gate:** tidak ada unresolved critical security finding, tenant escape tests lulus, restore memenuhi
RPO/RTO, dan installation/upgrade lulus di Linux/macOS/Windows.

## Template issue yang wajib digunakan

```markdown
## Goal

## Requirement IDs

## Threat scenarios

## Scope

## Out of scope

## Technical design

## Security/privacy considerations

## Test cases

## Acceptance criteria

## Rollback plan
```

Satu issue sebaiknya hanya mencakup satu fase dan satu scope yang dapat diverifikasi. Perubahan pada
policy enforcement, remediation, authentication, cryptography, atau tenant isolation wajib melalui
human security review sebelum merge.

## Definition of done untuk setiap pending item

- Requirement dan threat scenario terhubung.
- Schema/API versioned dan compatibility test tersedia.
- Unit, fixture, contract, dan integration test yang relevan lulus.
- Safe dan malicious fixtures tersedia tanpa credential/PII nyata.
- Evidence menjelaskan lokasi, alasan, confidence, dan remediation.
- Secret leakage, failure mode, timeout, resource limit, dan partial result diuji.
- Dokumentasi, migration, rollback, telemetry, privacy, dan accessibility diperbarui bila relevan.
- Acceptance criteria didemonstrasikan oleh test atau reproducible command, bukan hanya checklist.
