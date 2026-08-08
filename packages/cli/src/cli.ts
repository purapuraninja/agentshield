import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { Command } from 'commander';
import {
  VERSION, memoryAuditReportSchema, safeJson, scanReportSchema, severityRank,
  type MemoryAuditReport, type ScanReport, type Severity
} from '@agentshield/core';
import {
  addBaselineSuppressions, createBaseline, diffReports, evaluatePolicy, getRule, loadBaseline,
  loadPolicy, pruneExpiredSuppressions, saveBaseline, scanTarget, simulatePolicy, staticRules,
  validateBaseline, type StaticRule
} from '@agentshield/scanner';
import { renderAgentBom, renderHtml, renderMemoryAgentBom, renderMemoryEvidenceBundle, renderMemoryHtml, renderMemorySarif, renderSarif } from '@agentshield/reports';
import { auditMemory, classifyMemoryTypes, getMemoryRule, listQuarantine, memoryRules, quarantineMemory, reconcileMemoryInventory, restoreMemory, type AuditOptions,
  planRemediation, approveRemediation, executeRemediation, rollbackRemediation, rejectRemediation, listRemediationPlans, getRemediationPlan } from '@agentshield/memory';
import { EventStore, buildEvidenceGraph, createRuntimeEvent } from '@agentshield/runtime';
import {
  buildRulepack, deserializeRules, generateRulepackKeyPair, installRulepack, loadRulepackBundle,
  loadRulepackState, rollbackRulepack, verifyRulepack
} from '@agentshield/rulepack';
import {
  DEFAULT_CONSENT_PATH, appendConsentEvent, buildTelemetryDataPreview, consentState, readConsent
} from './telemetry.js';
import { SUPPORTED_SHELLS, completionScript, isSupportedShell } from './completions.js';

type ScanFormat = 'terminal' | 'json' | 'sarif' | 'html' | 'agentbom';
type MemoryFormat = 'terminal' | 'json' | 'html' | 'sarif' | 'agentbom' | 'bundle';

const program = new Command();
program.name('agentshield').description('Local-first security and memory hygiene for AI agents').version(VERSION);

function severityColor(severity: string): string {
  if (!process.stdout.isTTY || process.env.NO_COLOR) return severity.toUpperCase();
  const color = severity === 'critical' || severity === 'high' ? 31 : severity === 'medium' ? 33 : severity === 'low' ? 36 : 90;
  return `\u001b[${color}m${severity.toUpperCase()}\u001b[0m`;
}

function scanSummary(report: ScanReport): string {
  const lines = [
    '', 'AgentShield static scan', '────────────────────────────────────────────────────────',
    `Target       ${report.target}`, `Status       ${report.status}`, `Files        ${report.filesScanned}`,
    `Permissions  ${report.permissions.length}`, `Risk         ${report.overallRisk}/100`, ''
  ];
  const active = report.findings.filter((item) => item.status !== 'suppressed');
  if (!active.length) lines.push('✓ No deterministic rule matched. This is not a guarantee of safety.');
  else for (const finding of active) {
    const evidence = finding.evidence[0]!;
    lines.push(`${severityColor(finding.severity).padEnd(process.stdout.isTTY ? 18 : 10)} ${finding.ruleId}  ${finding.title}`);
    lines.push(`           ${evidence.path}${evidence.line ? `:${evidence.line}` : ''}`);
    lines.push(`           ${evidence.excerpt}`);
    lines.push(`           Fix: ${finding.remediation}`, '');
  }
  if (report.errors.length) lines.push(`Incomplete analysis: ${report.errors.length} file(s). See JSON report for details.`);
  return lines.join('\n');
}

function memorySummary(report: MemoryAuditReport): string {
  const lines = [
    '', 'AgentShield memory audit', '────────────────────────────────────────────────────────',
    `Target       ${report.target}`, `Adapter      ${report.adapter}`, `Records      ${report.inventory.audited}/${report.inventory.total}`,
    `Quarantined  ${report.inventory.quarantined}`, `Privacy      ${report.privacyMode}`,
    `Cache        ${report.cache?.enabled ? `${report.cache.hits} hit(s), ${report.cache.misses} miss(es)` : 'disabled'}`,
    `Findings     ${report.findings.length}`, ''
  ];
  for (const finding of report.findings) {
    lines.push(`${severityColor(finding.severity).padEnd(process.stdout.isTTY ? 18 : 10)} ${finding.ruleId}  ${finding.title}`);
    lines.push(`           memory=${String(finding.metadata.memoryId ?? 'unknown')}`);
    lines.push(`           ${finding.evidence[0]!.excerpt}`, '');
  }
  if (!report.findings.length) lines.push('✓ No configured memory detector matched.');
  return lines.join('\n');
}

async function emit(content: string, output?: string): Promise<void> {
  if (output) {
    const outputPath = resolve(output);
    await mkdir(dirname(outputPath), { recursive: true });
    await writeFile(outputPath, content.endsWith('\n') ? content : `${content}\n`, 'utf8');
    console.error(`Wrote ${outputPath}`);
  } else process.stdout.write(content.endsWith('\n') ? content : `${content}\n`);
}

function renderScan(report: ScanReport, format: ScanFormat): string {
  if (format === 'json') return safeJson(report);
  if (format === 'sarif') return JSON.stringify(renderSarif(report), null, 2);
  if (format === 'html') return renderHtml(report);
  if (format === 'agentbom') return JSON.stringify(renderAgentBom(report), null, 2);
  return scanSummary(report);
}

function shouldFail(report: ScanReport, threshold?: Severity): boolean {
  if (!threshold) return false;
  return report.findings.some((item) => item.status === 'open' && severityRank[item.severity] >= severityRank[threshold]);
}

interface ScanCommandOptions { format: ScanFormat; output?: string; failOn?: Severity; baseline?: string; policy?: string; ci?: boolean; rulepack?: string; rulepackKey?: string }
async function executeScan(target: string, options: ScanCommandOptions): Promise<ScanReport> {
  const baseline = options.baseline ? await loadBaseline(options.baseline) : undefined;
  let rules: StaticRule[] | undefined;
  if (options.rulepack) {
    if (!options.rulepackKey) throw new Error('--rulepack requires --rulepack-key <public.pem>');
    const publicKeyPem = await readFile(resolve(options.rulepackKey), 'utf8');
    const bundle = await loadRulepackBundle(resolve(options.rulepack));
    const verification = verifyRulepack(bundle, publicKeyPem);
    if (!verification.valid) throw new Error(`Rulepack rejected: ${verification.reasons.join('; ')}`);
    rules = deserializeRules(bundle.rules);
    console.error(`Using verified rulepack ${bundle.manifest.id} ${bundle.manifest.version} by ${bundle.manifest.publisher}`);
  }
  const report = await scanTarget(target, { baseline, rules });
  await emit(renderScan(report, options.format), options.output);
  if (options.policy) {
    const decision = evaluatePolicy(report, await loadPolicy(options.policy));
    console.error(`Policy decision: ${decision.action}${decision.matchedRules.length ? ` (${decision.matchedRules.join(', ')})` : ''}`);
    if (decision.action === 'block') process.exitCode = 2;
    else if (decision.action === 'require_review') process.exitCode = Math.max(Number(process.exitCode ?? 0), 3);
  }
  const threshold = options.failOn ?? (options.ci ? 'high' : undefined);
  if (shouldFail(report, threshold)) process.exitCode = 2;
  if (report.status === 'partial' && options.ci) process.exitCode = Math.max(Number(process.exitCode ?? 0), 4);
  return report;
}

function addScanOptions(command: Command): Command {
  return command
    .option('-f, --format <format>', 'terminal, json, sarif, html, or agentbom', 'terminal')
    .option('-o, --output <path>', 'write output to a file')
    .option('--fail-on <severity>', 'exit 2 at or above: low, medium, high, critical')
    .option('--baseline <path>', 'reviewed finding baseline')
    .option('--policy <path>', 'YAML policy file')
    .option('--rulepack <file>', 'scan with a verified signed rulepack bundle')
    .option('--rulepack-key <public.pem>', 'publisher public key required with --rulepack')
    .option('--ci', 'non-interactive CI defaults');
}

addScanOptions(program.command('scan <target>').description('Scan a file or directory without executing it'))
  .action(async (target, options) => { await executeScan(target, options); });
addScanOptions(program.command('scan-mcp <target>').description('Scan an MCP configuration or directory'))
  .action(async (target, options) => { await executeScan(target, options); });

program.command('permissions <target>').description('Print inferred capabilities and evidence').option('--json', 'JSON output')
  .action(async (target, options) => {
    const report = await scanTarget(target);
    if (options.json) return emit(safeJson(report.permissions));
    const lines = report.permissions.map((item) => `${severityColor(item.risk).padEnd(process.stdout.isTTY ? 18 : 10)} ${item.resource}.${item.action} [${item.scope}]  ${item.evidence.path}:${item.evidence.line ?? 1}`);
    await emit(lines.join('\n') || 'No permissions inferred.');
  });

program.command('diff <oldTarget> <newTarget>').description('Compare scan findings and risk between two targets').option('--json', 'JSON output')
  .action(async (oldTarget, newTarget, options) => {
    const oldReport = await loadOrScan(oldTarget); const newReport = await loadOrScan(newTarget);
    const diff = diffReports(oldReport, newReport);
    await emit(options.json ? safeJson(diff) : [
      `Risk delta: ${diff.riskDelta >= 0 ? '+' : ''}${diff.riskDelta}`, `Added: ${diff.added.length}`, `Removed: ${diff.removed.length}`, `Unchanged: ${diff.unchanged}`,
      ...diff.added.map((item) => `+ ${item.severity.toUpperCase()} ${item.ruleId} ${item.title}`),
      ...diff.removed.map((item) => `- ${item.severity.toUpperCase()} ${item.ruleId} ${item.title}`)
    ].join('\n'));
  });

async function loadOrScan(path: string): Promise<ScanReport> {
  if (path.toLowerCase().endsWith('.json')) {
    try { return scanReportSchema.parse(JSON.parse(await readFile(path, 'utf8'))); } catch { /* target may be a config */ }
  }
  return scanTarget(path);
}

const rulepack = program.command('rulepack').description('Build, verify, install, update, and roll back signed rulepacks');
rulepack.command('keygen').description('Generate an ed25519 publisher key pair')
  .option('--dir <path>', 'output directory', '.agentshield/keys')
  .action(async (options) => {
    const keys = generateRulepackKeyPair();
    const directory = resolve(options.dir);
    await mkdir(directory, { recursive: true });
    const privatePath = join(directory, 'agentshield-rulepack-private.pem');
    const publicPath = join(directory, 'agentshield-rulepack-public.pem');
    await writeFile(privatePath, keys.privateKeyPem, 'utf8');
    await writeFile(publicPath, keys.publicKeyPem, 'utf8');
    await emit(`Wrote private key to ${privatePath}\nWrote public key to ${publicPath}\nKeep the private key offline; distribute only the public key.`);
  });
rulepack.command('build <version> <publisher>').description('Build and sign a rulepack bundle from the built-in deterministic rules')
  .requiredOption('--key <private.pem>').requiredOption('-o, --output <path>')
  .action(async (version, publisher, options) => {
    const privateKeyPem = await readFile(resolve(options.key), 'utf8');
    const bundle = buildRulepack({ version, publisher, privateKeyPem });
    await emit(JSON.stringify(bundle, null, 2), options.output);
  });
rulepack.command('verify <bundle>').description('Verify the signature, publisher binding, and rule digest').requiredOption('--key <public.pem>')
  .option('--json', 'JSON output')
  .action(async (bundlePath, options) => {
    const publicKeyPem = await readFile(resolve(options.key), 'utf8');
    const bundle = await loadRulepackBundle(resolve(bundlePath));
    const verification = verifyRulepack(bundle, publicKeyPem);
    await emit(options.json ? safeJson(verification) : [
      verification.valid ? 'Signature: VALID' : 'Signature: INVALID',
      `Bundle: ${bundle.manifest.id} ${bundle.manifest.version}`, `Publisher: ${bundle.manifest.publisher}`,
      `Rules: ${bundle.manifest.ruleCount}`, ...verification.reasons.map((reason) => `- ${reason}`)
    ].join('\n'));
    if (!verification.valid) process.exitCode = 1;
  });
rulepack.command('install <bundle>').description('Verify against the publisher key and record as the current rulepack (update)')
  .requiredOption('--key <public.pem>').option('--store <dir>', 'local state directory', '.agentshield')
  .action(async (bundlePath, options) => {
    const publicKeyPem = await readFile(resolve(options.key), 'utf8');
    const bundle = await loadRulepackBundle(resolve(bundlePath));
    const result = await installRulepack(bundle, publicKeyPem, resolve(options.store));
    if (!result.verification.valid) throw new Error(`Rulepack rejected: ${result.verification.reasons.join('; ')}`);
    await emit(`Installed rulepack ${bundle.manifest.version} by ${bundle.manifest.publisher}\nCurrent: ${result.state.current}`);
  });
rulepack.command('list').description('List installed rulepacks and the current version')
  .option('--store <dir>', 'local state directory', '.agentshield').option('--json', 'JSON output')
  .action(async (options) => {
    const state = await loadRulepackState(resolve(options.store));
    await emit(options.json ? safeJson(state) : [
      `Current: ${state.current || '(none installed)'}`, ...state.installed.map((item) =>
        `${item.version}${item.version === state.current ? '  [current]' : ''}  ${item.publisher}  installed ${item.installedAt}`)
    ].join('\n'));
  });
rulepack.command('rollback').description('Switch to the highest installed version below the current one')
  .option('--store <dir>', 'local state directory', '.agentshield')
  .action(async (options) => {
    const result = await rollbackRulepack(resolve(options.store));
    if (!result.previous) throw new Error('Nothing to roll back to');
    await emit(`Rolled back to ${result.previous}`);
  });

const policy = program.command('policy').description('Evaluate policy-as-code');
policy.command('check <report> <policy>').description('Evaluate a JSON scan report against YAML policy').option('--json', 'JSON output')
  .action(async (reportPath, policyPath, options) => {
    const report = scanReportSchema.parse(JSON.parse(await readFile(reportPath, 'utf8')));
    const decision = evaluatePolicy(report, await loadPolicy(policyPath));
    await emit(options.json ? safeJson(decision) : `Decision: ${decision.action}\n${decision.reasons.join('\n')}`);
    if (decision.action === 'block') process.exitCode = 2;
    else if (decision.action === 'require_review') process.exitCode = 3;
  });
policy.command('simulate <policy> <reports...>').description('Evaluate a policy against multiple historical JSON reports')
  .option('--json', 'JSON output').option('--fail-on-block', 'exit 2 if any simulated report is blocked')
  .action(async (policyPath, reportPaths, options) => {
    const reports = await Promise.all((reportPaths as string[]).map(readScanReport));
    const simulation = simulatePolicy(reports, await loadPolicy(policyPath));
    await emit(options.json ? safeJson(simulation) : [
      `Policy: ${simulation.policyId} (schema v${simulation.policyVersion})`,
      `Reports: ${simulation.reports}`,
      `allow=${simulation.distribution.allow} warn=${simulation.distribution.warn} require_review=${simulation.distribution.require_review} quarantine=${simulation.distribution.quarantine} block=${simulation.distribution.block}`,
      ...simulation.results.map((result) => `${result.decision.action.padEnd(14)} ${result.scanId}  ${result.target}`)
    ].join('\n'));
    if (options.failOnBlock && simulation.distribution.block) process.exitCode = 2;
  });

program.command('report <input>').description('Convert a canonical JSON report').requiredOption('-f, --format <format>', 'html, sarif, or agentbom').option('-o, --output <path>')
  .action(async (input, options) => {
    const raw = JSON.parse(await readFile(input, 'utf8'));
    const scan = scanReportSchema.safeParse(raw);
    if (scan.success) return emit(renderScan(scan.data, options.format), options.output);
    const memory = memoryAuditReportSchema.parse(raw);
    if (options.format !== 'html') throw new Error('Memory reports currently convert to html only');
    return emit(renderMemoryHtml(memory), options.output);
  });

const rules = program.command('rules').description('Inspect the deterministic rulepack');
const ruleCatalog = [
  ...staticRules.map((rule) => ({
    id: rule.id, title: rule.title, description: rule.description, severity: rule.severity, confidence: rule.confidence,
    category: rule.category, remediation: rule.remediation, owner: rule.owner, reviewDate: rule.reviewDate,
    limitations: rule.limitations, kind: 'static' as const
  })),
  ...memoryRules.map((rule) => ({ ...rule, kind: 'memory' as const }))
];
rules.command('list').option('--json', 'JSON output').action(async (options) => {
  await emit(options.json ? safeJson(ruleCatalog) : ruleCatalog.map((rule) => `${rule.id}  ${rule.severity.toUpperCase().padEnd(8)} ${rule.title}`).join('\n'));
});
program.command('explain <ruleId>').description('Explain a static or memory rule').action(async (ruleId) => {
  const rule = getRule(ruleId) ?? getMemoryRule(ruleId); if (!rule) throw new Error(`Unknown rule: ${ruleId}`);
  await emit(`${rule.id} — ${rule.title}\nSeverity: ${rule.severity}\nConfidence: ${rule.confidence}\n\n${rule.description}\n\nRemediation: ${rule.remediation}\n\nLimitations: ${rule.limitations}\nOwner: ${rule.owner}\nReview date: ${rule.reviewDate}`);
});

const baselines = program.command('baseline').description('Manage reviewed, expiring finding suppressions');
baselines.command('create <report>').description('Create a baseline from open findings in a canonical scan report')
  .requiredOption('--owner <name>').requiredOption('--reason <text>').requiredOption('-o, --output <path>')
  .option('--expires-in-days <days>', 'expiry between 1 and 365 days', '30')
  .option('--minimum-severity <severity>', 'include findings at or above this severity')
  .option('--finding <fingerprints...>', 'include only exact finding fingerprints')
  .action(async (reportPath, options) => {
    const report = await readScanReport(reportPath);
    const baseline = createBaseline(report, {
      owner: options.owner, reason: options.reason, expiresInDays: baselineDays(options.expiresInDays),
      fingerprints: options.finding, minimumSeverity: baselineSeverity(options.minimumSeverity)
    });
    await saveBaseline(options.output, baseline);
    await emit(`Created ${baseline.suppressions.length} suppression(s) in ${resolve(options.output)}`);
  });
baselines.command('add <baseline> <report>').description('Add selected report findings to an existing baseline')
  .requiredOption('--owner <name>').requiredOption('--reason <text>').requiredOption('--finding <fingerprints...>')
  .option('-o, --output <path>', 'output path; defaults to replacing the input atomically')
  .option('--expires-in-days <days>', 'expiry between 1 and 365 days', '30')
  .action(async (baselinePath, reportPath, options) => {
    const current = await loadBaseline(baselinePath);
    const updated = addBaselineSuppressions(current, await readScanReport(reportPath), {
      owner: options.owner, reason: options.reason, expiresInDays: baselineDays(options.expiresInDays), fingerprints: options.finding
    });
    const output = options.output ?? baselinePath;
    await saveBaseline(output, updated);
    await emit(`Added ${updated.suppressions.length - current.suppressions.length} suppression(s); total ${updated.suppressions.length} in ${resolve(output)}`);
  });
baselines.command('validate <baseline>').description('Validate ownership, reasons, fingerprints, duplicates, and expiry').option('--json', 'JSON output')
  .action(async (baselinePath, options) => {
    const value = JSON.parse(await readFile(baselinePath, 'utf8')) as unknown;
    const validation = validateBaseline(value);
    await emit(options.json ? safeJson(validation) : [
      `Valid: ${validation.valid ? 'yes' : 'no'}`, `Active: ${validation.active}`, `Expired: ${validation.expired}`,
      ...(validation.invalid.length ? ['Issues:', ...validation.invalid.map((issue) => `- ${issue}`)] : [])
    ].join('\n'));
    if (!validation.valid) process.exitCode = 4;
    else if (validation.expired) process.exitCode = 3;
  });
baselines.command('prune <baseline>').description('Remove expired suppressions while preserving active review records')
  .option('-o, --output <path>', 'output path; defaults to replacing the input atomically')
  .action(async (baselinePath, options) => {
    const current = await loadBaseline(baselinePath);
    const result = pruneExpiredSuppressions(current);
    const output = options.output ?? baselinePath;
    await saveBaseline(output, result.baseline);
    await emit(`Removed ${result.removed.length} expired suppression(s); ${result.baseline.suppressions.length} active in ${resolve(output)}`);
  });

async function readScanReport(path: string): Promise<ScanReport> {
  return scanReportSchema.parse(JSON.parse(await readFile(path, 'utf8')));
}

function baselineDays(value: string): number {
  const days = Number(value);
  if (!Number.isInteger(days) || days < 1 || days > 365) throw new Error('--expires-in-days must be an integer between 1 and 365');
  return days;
}

function baselineSeverity(value?: string): Severity | undefined {
  if (!value) return;
  if (!(value in severityRank)) throw new Error('--minimum-severity must be info, low, medium, high, or critical');
  return value as Severity;
}

const memory = program.command('memory').description('Audit and safely remediate agent memory');
memory.command('audit <target>').description('Read-only memory audit')
  .option('-f, --format <format>', 'terminal, json, html, sarif, agentbom, or bundle', 'terminal').option('-o, --output <path>')
  .option('--privacy <mode>', 'none, secrets, pii-secrets, or metadata-only', 'pii-secrets')
  .option('--no-cache', 'disable the local incremental assessment cache')
  .option('--page-size <count>', 'inventory records requested per adapter page', '500')
  .option('--table <name>').option('--id-column <name>').option('--content-column <name>').option('--created-at-column <name>').option('--source-column <name>')
  .action(async (target, options) => {
    const adapterOptions = memoryOptions(options); const report = await auditMemory(target, adapterOptions);
    const format = options.format as MemoryFormat;
    const output = format === 'json' ? safeJson(report)
      : format === 'html' ? renderMemoryHtml(report)
      : format === 'sarif' ? safeJson(renderMemorySarif(report))
      : format === 'agentbom' ? safeJson(renderMemoryAgentBom(report))
      : format === 'bundle' ? safeJson(renderMemoryEvidenceBundle(report))
      : memorySummary(report);
    await emit(output, options.output);
  });
memory.command('quarantine <target> <memoryId>').description('Quarantine a record locally without deleting its source')
  .requiredOption('--actor <name>').requiredOption('--reason <text>')
  .option('--table <name>').option('--id-column <name>').option('--content-column <name>')
  .action(async (target, memoryId, options) => emit(safeJson(await quarantineMemory(target, memoryId, options.actor, options.reason, memoryOptions(options)))));
memory.command('restore <target> <memoryId>').description('Restore a quarantined record').requiredOption('--actor <name>').requiredOption('--reason <text>')
  .action(async (target, memoryId, options) => emit(safeJson(await restoreMemory(target, memoryId, options.actor, options.reason))));
memory.command('quarantine-list <target>').description('List local quarantine metadata (snapshots omitted)').action(async (target) => emit(safeJson(await listQuarantine(target))));

const remediation = program.command('remediation').description('Plan, approve, execute, and roll back reversible memory remediation');
remediation.command('plan <target> <memoryId> <action>').description('Plan a quarantine, restore, or deprecate (records a persisted plan without mutating the source)')
  .requiredOption('--actor <name>').requiredOption('--reason <text>').option('--idempotency-key <key>').option('--two-person')
  .action(async (target, memoryId, action, options) => emit(safeJson(await planRemediation(target, memoryId, action as 'quarantine' | 'restore' | 'deprecate', options.actor, options.reason, { idempotencyKey: options.idempotencyKey, requireTwoPerson: options.twoPerson === true }))));
remediation.command('approve <target> <planId>').description('Approve a planned remediation').requiredOption('--actor <name>').requiredOption('--reason <text>')
  .action(async (target, planId, options) => emit(safeJson(await approveRemediation(target, planId, options.actor, options.reason))));
remediation.command('execute <target> <planId>').description('Execute an approved plan (compare-and-swap guards the source hash)').requiredOption('--actor <name>')
  .action(async (target, planId, options) => emit(safeJson(await executeRemediation(target, planId, options.actor))));
remediation.command('rollback <target> <planId>').description('Reverse an executed plan').requiredOption('--actor <name>').requiredOption('--reason <text>')
  .action(async (target, planId, options) => emit(safeJson(await rollbackRemediation(target, planId, options.actor, options.reason))));
remediation.command('reject <target> <planId>').description('Reject a planned or approved plan').requiredOption('--actor <name>').requiredOption('--reason <text>')
  .action(async (target, planId, options) => emit(safeJson(await rejectRemediation(target, planId, options.actor, options.reason))));
remediation.command('list <target>').description('List remediation plans').action(async (target) => emit(safeJson(await listRemediationPlans(target))));
remediation.command('get <target> <planId>').description('Show a single remediation plan').action(async (target, planId) => emit(safeJson(await getRemediationPlan(target, planId) ?? { error: `Plan not found: ${planId}` })));
memory.command('reconcile <target>').description('Reconcile audited inventory against the source store with documented exclusions').action(async (target) => emit(safeJson(await reconcileMemoryInventory(target, memoryOptions({})))));
memory.command('classify <target>').description('Classify memory record types with evidence').action(async (target) => emit(safeJson(await classifyMemoryTypes(target, memoryOptions({})))));

function memoryOptions(options: Record<string, string | boolean | undefined>): AuditOptions {
  const pageSize = options.pageSize === undefined ? undefined : Number(options.pageSize);
  return {
    privacyMode: options.privacy as AuditOptions['privacyMode'],
    table: options.table as string | undefined,
    idColumn: options.idColumn as string | undefined,
    contentColumn: options.contentColumn as string | undefined,
    createdAtColumn: options.createdAtColumn as string | undefined,
    sourceColumn: options.sourceColumn as string | undefined,
    cache: options.cache !== false,
    pageSize
  };
}

const runtime = program.command('runtime').description('Ingest and inspect sanitized runtime evidence');
runtime.command('ingest <input>').description('Ingest a JSON event or JSONL event stream').option('--store <path>', 'event store path', '.agentshield/events.jsonl')
  .action(async (input, options) => {
    const content = await readFile(input, 'utf8'); const store = new EventStore(resolve(options.store)); let accepted = 0; let duplicates = 0;
    for (const line of content.split(/\r?\n/).filter(Boolean)) {
      const raw = JSON.parse(line); const event = 'schemaVersion' in raw ? raw : createRuntimeEvent(raw);
      const result = await store.ingest(event);
      if (result.duplicate) duplicates++; else accepted++;
    }
    await emit(`Accepted: ${accepted}\nDuplicates: ${duplicates}`);
  });
runtime.command('trace <traceId>').description('Build a source-to-action evidence graph').option('--store <path>', 'event store path', '.agentshield/events.jsonl').option('--json', 'JSON output')
  .action(async (traceId, options) => {
    const events = await new EventStore(resolve(options.store)).trace(traceId); const graph = buildEvidenceGraph(events, traceId);
    await emit(options.json ? safeJson(graph) : [
      `Trace ${traceId}`, ...events.map((item) => `${item.timestamp}  ${item.type.padEnd(22)} ${item.target ?? item.actor}`),
      ...(graph.gaps.length ? ['Evidence gaps:', ...graph.gaps.map((gap) => `- ${gap}`)] : ['Evidence chain complete for recorded event types.'])
    ].join('\n'));
  });

const telemetry = program.command('telemetry').description('Manage local telemetry consent (off by default; nothing is transmitted in the Community edition)');
telemetry.command('status').description('Show the current consent state and receipt history')
  .option('--store <path>', 'consent file path', DEFAULT_CONSENT_PATH)
  .action(async (options) => {
    const file = await readConsent(resolve(options.store));
    const state = consentState(file);
    const last = file.events.at(-1);
    await emit(`Telemetry: ${state === 'enabled' ? 'ENABLED' : 'disabled (default)'}\nConsent events: ${file.events.length}${last ? `\nLast: ${last.action} by ${last.actor} at ${last.timestamp} — ${last.reason}` : ''}`);
  });
telemetry.command('enable').description('Opt in to telemetry and record a consent receipt').requiredOption('--actor <name>').requiredOption('--reason <text>')
  .option('--store <path>', 'consent file path', DEFAULT_CONSENT_PATH)
  .action(async (options) => emit(safeJson(await appendConsentEvent(resolve(options.store), 'enable', options.actor, options.reason))));
telemetry.command('disable').description('Revoke telemetry consent and record a receipt').requiredOption('--actor <name>').requiredOption('--reason <text>')
  .option('--store <path>', 'consent file path', DEFAULT_CONSENT_PATH)
  .action(async (options) => emit(safeJson(await appendConsentEvent(resolve(options.store), 'disable', options.actor, options.reason))));
telemetry.command('preview').description('Preview the telemetry schema that an opt-in could collect (nothing is sent)')
  .option('--json', 'JSON output')
  .action(async (options) => {
    const preview = buildTelemetryDataPreview();
    await emit(options.json ? safeJson(preview) : [
      'AgentShield telemetry data preview (nothing is transmitted)', '',
      'Metrics:', ...preview.metrics.map((metric) => `- ${metric.name}: ${metric.description}`),
      '', `Exclusions: ${preview.exclusions.join(', ')}`, '', preview.note
    ].join('\n'));
  });

program.command('completion <shell>').description(`Print a shell completion script (${SUPPORTED_SHELLS.join(', ')}). Source it or write it to your completion directory.`)
  .action(async (shell) => {
    if (!isSupportedShell(shell)) throw new Error(`Unsupported shell: ${shell}. Supported: ${SUPPORTED_SHELLS.join(', ')}`);
    await emit(completionScript(shell));
  });

program.showHelpAfterError();
program.configureOutput({ outputError: (message, write) => write(`AgentShield: ${message}`) });

program.parseAsync(process.argv).catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`AgentShield error: ${message}`);
  process.exitCode = 1;
});
