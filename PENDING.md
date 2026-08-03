# AgentShield — Pending Implementation

Dokumen ini adalah gap analysis antara `AGENTSHIELD_DEVELOPMENT_PLAN.md` dan implementasi lokal
v0.1.0 saat ini. Tujuannya adalah menjelaskan apa yang belum selesai, mengapa belum dianggap
production-ready, serta urutan implementasi yang aman.

Terakhir diperbarui: 2026-08-03.

## Arti status

- `[ ]` belum diimplementasikan.
- `[~]` sudah ada implementasi dasar, tetapi belum memenuhi acceptance criteria rencana utama.
- `[x]` sudah tersedia di v0.1.0 dan tidak dibahas kembali kecuali masih mempunyai gap.

## Baseline yang sudah tersedia

- [x] CLI lokal, schema Zod, static scanner, permission map, dan 24 deterministic supply-chain
  rules.
- [x] Laporan JSON, SARIF, HTML, serta CycloneDX-compatible AgentBOM.
- [x] YAML policy evaluation, baseline consumption, diff, CI exit code, rule list, dan explain.
- [x] Audit read-only untuk JSON, JSONL, Markdown, serta SQLite.
- [x] Deteksi dasar untuk stale/expired memory, exact/near duplicate, konflik EAV sederhana, secret,
  PII, dan instruction-like poisoning.
- [x] Quarantine/restore lokal berbasis sidecar dengan snapshot dan hash-chained audit log.
- [x] Sanitized runtime event store dan evidence graph lokal.
- [x] Loopback REST API dan dashboard lokal untuk overview, scan, findings, serta permissions.
- [x] Lint, typecheck, 16 automated tests, cross-platform CI skeleton, Docker API, dan fixtures dasar.

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

- [~] JavaScript/TypeScript, Python, dan shell masih dianalisis terutama dengan regular expression,
  belum dengan AST/control-flow representation.
- [~] JSON dan YAML divalidasi, tetapi TOML belum diparse secara struktural.
- [~] Markdown belum mempunyai parser front matter, link, command, code block, hidden Unicode, dan
  instruction phrase yang terpisah.
- [~] Rule `AS-SC-001` hanya taint-lite dalam satu file; belum membuktikan secret benar-benar mencapai
  network sink.
- [~] MCP tool mismatch hanya heuristic teks; belum membandingkan tool schema, declared permissions,
  dan implementasi handler.
- [~] Discovery sudah menghormati `.gitignore`/`.agentshieldignore`, tetapi belum memindai archive,
  package metadata, lockfile provenance, Git ref, checksum, atau signature.
- [ ] Dukungan packaged extension seperti `.zip`, `.tgz`, wheel, dan npm tarball dengan proteksi
  archive bomb/path traversal.
- [ ] Rulepack manifest bertanda tangan, updater, rollback rulepack, dan verifikasi publisher.
- [ ] Optional sandboxed dynamic analysis.

### Cara mengimplementasikan

1. Tambahkan package `packages/parsers` dan common intermediate representation:
   `FileNode`, `CallNode`, `DataSource`, `DataSink`, `ToolDefinition`, serta `ParseDiagnostic`.
2. Gunakan TypeScript Compiler API untuk JS/TS, Python worker terisolasi berbasis `ast`, parser shell
   yang tidak mengeksekusi input, `remark` untuk Markdown, serta parser JSON/YAML/TOML yang strict.
3. Ubah rule engine agar rule menerima IR, bukan raw text. Regex tetap dipakai sebagai conservative
   fallback dan setiap fallback harus menurunkan confidence atau menghasilkan analysis gap.
4. Bangun intra-file data flow untuk source `process.env`, credential files, dan secret manager output
   menuju sink `fetch`, HTTP clients, messaging, logs, atau child process.
5. Untuk MCP, normalkan server, tools, input schema, annotations, declared side effects, dan handler
   references. Bandingkan destructive implementation dengan description/approval declaration.
6. Ekstrak package name, exact version, repository URL, lockfile resolution, integrity hash, container
   digest, dan signature status ke component inventory.
7. Untuk archive, ekstrak hanya ke temporary directory dengan batas jumlah file, total expanded size,
   compression ratio, depth, dan canonical path containment.

### Acceptance criteria

- [ ] Parser tidak pernah mengeksekusi target.
- [ ] Semua parse failure menjadi `AS-SC-900` dengan format, file, dan alasan yang stabil.
- [ ] Critical fixture recall 100% untuk skenario deterministic yang didefinisikan.
- [ ] High-severity false-positive rate di bawah 10% pada safe corpus.
- [ ] Scan 10.000 file selesai di bawah lima menit pada mesin referensi 4-vCPU.
- [ ] Archive bomb, symlink escape, path traversal, dan file lebih besar dari limit tidak merusak host.

## 2. Rule quality, fixtures, dan benchmark — P0

- [~] Ada fixtures aman/rentan dan tests untuk rule paling penting, tetapi belum ada golden tests untuk
  setiap rule.
- [ ] Minimal satu true-positive dan dua safe negative fixture per production rule.
- [ ] Corpus minimal 30 extension publik dan 15 intentionally vulnerable fixtures untuk T-01–T-10.
- [ ] Corpus multilingual, khususnya instruksi Indonesia dan Inggris.
- [ ] Precision, recall, suppression rate, dan false-positive rate per rule.
- [ ] Rule owner review workflow dan automated review-date warning.
- [ ] Mutation/fuzz tests untuk parser dan malformed memory.

### Cara mengimplementasikan

1. Buat `fixtures/rules/<rule-id>/{positive,negative}/` dan metadata expected result dalam JSON.
2. Buat fixture runner yang memindai seluruh corpus dan membandingkan rule ID, severity, confidence,
   normalized evidence, serta remediation.
3. Tambahkan `benchmarks/scanner.ts` dengan fixture generator 1k/10k file dan simpan hasil per commit.
4. Tambahkan job terjadwal untuk fuzzing dan benchmark; jangan menjalankan malicious fixture di host
   production.
5. Publikasikan metrik kualitas rule di generated documentation.

## 3. CLI, reports, policy, dan distribution — P0/P1

- [~] Baseline dapat dibaca, tetapi belum ada command untuk membuat, meninjau, memperbarui, atau
  mendeteksi suppression kedaluwarsa.
- [~] Policy mendukung kondisi dasar; belum ada nested boolean expression, project/org scope,
  version history, simulator, atau exception approval.
- [ ] Signed rulepack update command dan offline rulepack bundle.
- [ ] Telemetry opt-in command, consent receipt, dan data preview. Default harus tetap off.
- [ ] npm release pipeline, changelog automation, artifact signing, checksum, SBOM, dan provenance
  attestation.
- [ ] Shell completions, man page, upgrade/uninstall documentation.
- [ ] Memory SARIF/AgentBOM export dan evidence bundle export.
- [ ] GitHub Action reusable resmi serta generic CI examples untuk GitLab/Azure/Jenkins.

### Cara mengimplementasikan

1. Tambahkan `baseline create`, `baseline add`, `baseline prune`, dan `baseline validate`. Setiap entry
   wajib mempunyai owner, reason, finding fingerprint, dan expiry.
2. Definisikan policy schema versioned dengan `all`, `any`, `not`, typed operands, dan deterministic
   evaluation trace. Jangan memakai `eval`.
3. Simpan policy versions immutable; publish policy baru melalui simulation terhadap historical
   reports sebelum aktivasi.
4. Buat release workflow yang menjalankan test, pack smoke test, menghasilkan CycloneDX SBOM,
   menandatangani tarball/checksum, lalu mempublikasikan hanya dari protected tag.

## 4. Memory adapters dan inventory — P0

- [~] JSON/JSONL/Markdown/SQLite tersedia, tetapi belum memakai adapter SDK/capability declaration
  formal.
- [~] Checkpoint hash dihasilkan, tetapi repeated scan masih memproses semua record; incremental cache
  belum ada.
- [ ] Generic PostgreSQL read-only adapter.
- [ ] Satu vector database adapter pertama; keputusan produk masih diperlukan.
- [ ] Pagination, checkpoints per source, retry, rate limit, dan per-record failure isolation formal.
- [ ] Source-store total reconciliation dan documented exclusions.
- [ ] Connection credential guidance serta automated least-privilege validation.
- [ ] Memory type classification yang evidence-backed.

### Cara mengimplementasikan

1. Definisikan `MemoryAdapter` dengan method `testConnection`, `capabilities`, `inventoryPage`,
   `checkpoint`, `planMutation`, `applyMutation`, dan `restoreSnapshot`.
2. Buat conformance suite yang wajib dilewati setiap adapter, termasuk proof bahwa audit mode tidak
   dapat memanggil write method.
3. Simpan cache berdasarkan adapter ID, external ID, content hash, detector version, dan privacy mode.
   Reuse assessment hanya jika semua key cocok.
4. Gunakan role database read-only, transaction read-only, query timeout, page size, dan maximum
   record size.
5. Pilih vector database berdasarkan design partner; kandidat awal: pgvector bila ingin mengurangi
   jumlah infrastruktur, atau Qdrant bila standalone vector workflow menjadi prioritas.

### Acceptance criteria

- [ ] Repeated scan hanya menghitung ulang record yang berubah.
- [ ] Satu record rusak tidak menggagalkan seluruh audit.
- [ ] Inventory totals cocok dengan source store dalam documented exclusions.
- [ ] Tidak ada write query yang dapat dijalankan saat audit mode.
- [ ] Raw memory tidak masuk log atau cloud event secara default.

## 5. Memory intelligence — P0/P1

- [~] Near duplicate masih memakai token Jaccard, bukan embedding atau semantic similarity.
- [~] Conflict detection hanya pola entity/attribute/value sederhana pada awal teks.
- [~] Freshness memakai umur generik; belum mempertimbangkan volatility, source modified time,
  memory type policy, atau authoritative replacement.
- [~] PII detector masih terbatas dan belum mempunyai locale packs atau organization terms.
- [~] Poison detector masih phrase matching; belum mendeteksi hidden Unicode, encoding, policy
  conflict, provenance mismatch, atau indirect tool instruction secara menyeluruh.
- [ ] Corroboration dari beberapa independent sources.
- [ ] Optional LLM classifier dengan cited memory IDs, pinned evals, local-model option, dan label
  yang membedakan hasil model dari deterministic findings.
- [ ] Conflict explorer API/UI.

### Cara mengimplementasikan

1. Tambahkan detector interface versioned dan simpan detector version di assessment.
2. Gunakan local embedding model atau configured embedding provider hanya setelah redaction/consent;
   simpan vector secara lokal dan gunakan threshold yang dikalibrasi dari corpus.
3. Ekstrak EAV + temporal qualifier, kelompokkan per normalized entity/attribute, lalu pilih conflict
   hanya jika value berbeda dan validity windows overlap.
4. Buat freshness policy per label/type: volatility, default TTL, grace period, authoritative source,
   serta review cadence.
5. Tambahkan Unicode normalization, zero-width character detection, base64/HTML-hidden instruction
   analysis, dan policy-versus-memory comparison.
6. LLM output hanya boleh menambah `assisted` finding; tidak boleh sendiri memblokir, menghapus, atau
   menulis ulang memory.

## 6. Remediation, versioning, dan rollback — P1

- [~] Quarantine sidecar melindungi audit AgentShield berikutnya, tetapi belum menghentikan retrieval
  oleh framework/agent di luar AgentShield.
- [~] Snapshot lokal tersedia, tetapi belum ada backup verification, encrypted snapshot store,
  retention, atau snapshot garbage collection.
- [ ] Connector write hooks untuk record-level quarantine/deprecation/TTL.
- [ ] Dry-run diff yang spesifik untuk source store.
- [ ] Immutable memory version service.
- [ ] Atomic batch mutation, partial-failure recovery, dan idempotency key.
- [ ] Two-person approval untuk high-impact batch.
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
- [ ] Missing draft endpoints: scan cancel, global components/permissions, remediation approve,
  execute, rollback, evidence export, policy versioning, dan pagination.
- [ ] Idempotency keys pada semua mutation/event endpoints.
- [ ] Cursor pagination, request schema/OpenAPI, rate limiting, timeouts, cancellation, dan stable
  error catalog.
- [ ] Structured logging, metrics, OpenTelemetry traces, readiness/liveness, dan queue health.
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
- [ ] Memory inventory/health view, conflict explorer, dan poisoning review queue.
- [ ] Quarantine plan, approval, execution, restore, dan rollback center.
- [ ] Runtime trace graph explorer dengan evidence-gap visualization.
- [ ] Policy editor, validator, simulator, version history, publish, dan rollback.
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

- [~] Ada API Dockerfile dan local Compose, tetapi belum ada dashboard/worker image, PostgreSQL,
  Redis, object storage, migrations, atau health-based orchestration.
- [ ] Production Dockerfiles dengan non-root user, read-only filesystem, pinned digest, dan image
  signing.
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
