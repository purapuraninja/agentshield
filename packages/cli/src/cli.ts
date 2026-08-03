import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { Command } from 'commander';
import {
  VERSION, memoryAuditReportSchema, safeJson, scanReportSchema, severityRank,
  type MemoryAuditReport, type ScanReport, type Severity
} from '@agentshield/core';
import {
  diffReports, evaluatePolicy, getRule, loadBaseline, loadPolicy, scanTarget, staticRules
} from '@agentshield/scanner';
import { renderAgentBom, renderHtml, renderMemoryHtml, renderSarif } from '@agentshield/reports';
import { auditMemory, listQuarantine, quarantineMemory, restoreMemory, type AuditOptions } from '@agentshield/memory';
import { EventStore, buildEvidenceGraph, createRuntimeEvent } from '@agentshield/runtime';

type ScanFormat = 'terminal' | 'json' | 'sarif' | 'html' | 'agentbom';
type MemoryFormat = 'terminal' | 'json' | 'html';

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
    `Quarantined  ${report.inventory.quarantined}`, `Privacy      ${report.privacyMode}`, `Findings     ${report.findings.length}`, ''
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

interface ScanCommandOptions { format: ScanFormat; output?: string; failOn?: Severity; baseline?: string; policy?: string; ci?: boolean }
async function executeScan(target: string, options: ScanCommandOptions): Promise<ScanReport> {
  const baseline = options.baseline ? await loadBaseline(options.baseline) : undefined;
  const report = await scanTarget(target, { baseline });
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

const policy = program.command('policy').description('Evaluate policy-as-code');
policy.command('check <report> <policy>').description('Evaluate a JSON scan report against YAML policy').option('--json', 'JSON output')
  .action(async (reportPath, policyPath, options) => {
    const report = scanReportSchema.parse(JSON.parse(await readFile(reportPath, 'utf8')));
    const decision = evaluatePolicy(report, await loadPolicy(policyPath));
    await emit(options.json ? safeJson(decision) : `Decision: ${decision.action}\n${decision.reasons.join('\n')}`);
    if (decision.action === 'block') process.exitCode = 2;
    else if (decision.action === 'require_review') process.exitCode = 3;
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
rules.command('list').option('--json', 'JSON output').action(async (options) => {
  await emit(options.json ? safeJson(staticRules) : staticRules.map((rule) => `${rule.id}  ${rule.severity.toUpperCase().padEnd(8)} ${rule.title}`).join('\n'));
});
program.command('explain <ruleId>').description('Explain a static rule').action(async (ruleId) => {
  const rule = getRule(ruleId); if (!rule) throw new Error(`Unknown rule: ${ruleId}`);
  await emit(`${rule.id} — ${rule.title}\nSeverity: ${rule.severity}\nConfidence: ${rule.confidence}\n\n${rule.description}\n\nRemediation: ${rule.remediation}\n\nLimitations: ${rule.limitations}\nOwner: ${rule.owner}\nReview date: ${rule.reviewDate}`);
});

const memory = program.command('memory').description('Audit and safely remediate agent memory');
memory.command('audit <target>').description('Read-only memory audit')
  .option('-f, --format <format>', 'terminal, json, or html', 'terminal').option('-o, --output <path>')
  .option('--privacy <mode>', 'none, secrets, pii-secrets, or metadata-only', 'pii-secrets')
  .option('--table <name>').option('--id-column <name>').option('--content-column <name>').option('--created-at-column <name>').option('--source-column <name>')
  .action(async (target, options) => {
    const adapterOptions = memoryOptions(options); const report = await auditMemory(target, adapterOptions);
    const format = options.format as MemoryFormat;
    await emit(format === 'json' ? safeJson(report) : format === 'html' ? renderMemoryHtml(report) : memorySummary(report), options.output);
  });
memory.command('quarantine <target> <memoryId>').description('Quarantine a record locally without deleting its source')
  .requiredOption('--actor <name>').requiredOption('--reason <text>')
  .option('--table <name>').option('--id-column <name>').option('--content-column <name>')
  .action(async (target, memoryId, options) => emit(safeJson(await quarantineMemory(target, memoryId, options.actor, options.reason, memoryOptions(options)))));
memory.command('restore <target> <memoryId>').description('Restore a quarantined record').requiredOption('--actor <name>').requiredOption('--reason <text>')
  .action(async (target, memoryId, options) => emit(safeJson(await restoreMemory(target, memoryId, options.actor, options.reason))));
memory.command('quarantine-list <target>').description('List local quarantine metadata (snapshots omitted)').action(async (target) => emit(safeJson(await listQuarantine(target))));

function memoryOptions(options: Record<string, string | undefined>): AuditOptions {
  return { privacyMode: options.privacy as AuditOptions['privacyMode'], table: options.table, idColumn: options.idColumn, contentColumn: options.contentColumn, createdAtColumn: options.createdAtColumn, sourceColumn: options.sourceColumn };
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

program.showHelpAfterError();
program.configureOutput({ outputError: (message, write) => write(`AgentShield: ${message}`) });

program.parseAsync(process.argv).catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`AgentShield error: ${message}`);
  process.exitCode = 1;
});
