import { readFile, readdir, stat } from 'node:fs/promises';
import { basename, dirname, extname, join, relative, resolve } from 'node:path';
import ignore, { type Ignore } from 'ignore';
import YAML from 'yaml';
import {
  SCHEMA_VERSION, VERSION, calculateOverallRisk, createId, maskEvidence, normalizePath, redactSecrets,
  scanReportSchema, sha256, severityRank, type Component, type Finding, type Permission,
  type RiskDimensions, type ScanReport, type Severity
} from '@agentshield/core';
import { staticRules, type StaticRule } from './rules.js';

export { getRule, staticRules, type StaticRule } from './rules.js';
export { evaluatePolicy, loadPolicy, type PolicyFile, type PolicyRule } from './policy.js';

const SUPPORTED_EXTENSIONS = new Set([
  '.md', '.mdx', '.json', '.jsonl', '.yaml', '.yml', '.toml', '.js', '.mjs', '.cjs', '.ts', '.tsx',
  '.jsx', '.py', '.sh', '.bash', '.zsh', '.ps1', '.html', '.htm'
]);
const ALWAYS_IGNORED = ['.git/', 'node_modules/', 'dist/', 'build/', 'coverage/', '.agentshield/'];
const MAX_FILE_BYTES = 2 * 1024 * 1024;

interface DiscoveredFile { absolute: string; relative: string; size: number }
export interface ScanOptions { baseline?: Baseline; maxFileBytes?: number }
export interface Baseline { version: 1; suppressions: Array<{ fingerprint: string; owner: string; reason: string; expiresAt: string }> }

async function buildIgnore(root: string): Promise<Ignore> {
  const matcher = ignore().add(ALWAYS_IGNORED);
  for (const name of ['.gitignore', '.agentshieldignore']) {
    try { matcher.add(await readFile(join(root, name), 'utf8')); } catch { /* optional */ }
  }
  return matcher;
}

async function discover(target: string, maxFileBytes: number): Promise<{ files: DiscoveredFile[]; errors: string[] }> {
  const absoluteTarget = resolve(target);
  const targetStat = await stat(absoluteTarget);
  const root = targetStat.isDirectory() ? absoluteTarget : dirname(absoluteTarget);
  const matcher = await buildIgnore(root);
  const files: DiscoveredFile[] = [];
  const errors: string[] = [];

  async function walk(path: string): Promise<void> {
    let entries;
    try { entries = await readdir(path, { withFileTypes: true }); }
    catch (error) { errors.push(`${normalizePath(relative(root, path))}: ${String(error)}`); return; }
    for (const entry of entries) {
      const absolute = join(path, entry.name);
      const rel = normalizePath(relative(root, absolute));
      if (matcher.ignores(rel + (entry.isDirectory() ? '/' : ''))) continue;
      if (entry.isSymbolicLink()) { errors.push(`${rel}: symbolic link skipped`); continue; }
      if (entry.isDirectory()) await walk(absolute);
      else if (entry.isFile() && (SUPPORTED_EXTENSIONS.has(extname(entry.name).toLowerCase()) || /^skill\.md$/i.test(entry.name))) {
        const info = await stat(absolute);
        if (info.size > maxFileBytes) errors.push(`${rel}: exceeds ${maxFileBytes} byte limit`);
        else files.push({ absolute, relative: rel || entry.name, size: info.size });
      }
    }
  }

  if (targetStat.isFile()) {
    if (targetStat.size <= maxFileBytes) files.push({ absolute: absoluteTarget, relative: basename(absoluteTarget), size: targetStat.size });
    else errors.push(`${basename(absoluteTarget)}: exceeds ${maxFileBytes} byte limit`);
  } else await walk(absoluteTarget);
  files.sort((a, b) => a.relative.localeCompare(b.relative));
  return { files, errors };
}

function lineAndColumn(content: string, index: number): { line: number; column: number; sourceLine: string } {
  const before = content.slice(0, index);
  const line = before.split('\n').length;
  const column = index - before.lastIndexOf('\n');
  return { line, column, sourceLine: content.split(/\r?\n/)[line - 1] ?? '' };
}

function fingerprint(ruleId: string, path: string, excerpt: string): string {
  return sha256(`${ruleId}\0${normalizePath(path)}\0${excerpt.trim().toLowerCase()}`);
}

function makeFinding(rule: StaticRule, path: string, content: string, match: RegExpExecArray): Finding {
  const location = lineAndColumn(content, match.index);
  const excerpt = maskEvidence(location.sourceLine || match[0]);
  return {
    id: fingerprint(rule.id, path, excerpt), ruleId: rule.id, title: rule.title, description: rule.description,
    severity: rule.severity, confidence: rule.confidence, category: rule.category,
    evidence: [{ path: normalizePath(path), line: location.line, column: location.column, excerpt, redacted: excerpt.includes('[REDACTED:') }],
    remediation: rule.remediation, status: 'open', metadata: { limitations: rule.limitations, owner: rule.owner, reviewDate: rule.reviewDate }
  };
}

function scanRules(path: string, content: string): Finding[] {
  const extension = extname(path).toLowerCase();
  const findings: Finding[] = [];
  for (const rule of staticRules) {
    if (rule.extensions && !rule.extensions.includes(extension)) continue;
    for (const pattern of rule.patterns) {
      const flags = pattern.flags.replace('g', '');
      const matcher = new RegExp(pattern.source, flags);
      const match = matcher.exec(content);
      if (match) { findings.push(makeFinding(rule, path, content, match)); break; }
    }
  }
  return findings;
}

function secretNetworkChain(path: string, content: string): Finding | undefined {
  const secret = /process\.env|os\.(?:environ|getenv)|\$env:|(?:API_KEY|TOKEN|SECRET|PASSWORD)/i.exec(content);
  const network = /fetch\s*\(|axios\.|requests\.|https?\.request|curl\b|Invoke-(?:WebRequest|RestMethod)/i.exec(content);
  if (!secret || !network) return;
  const rule: StaticRule = {
    id: 'AS-SC-001', title: 'Secret access and network sink in the same file', severity: 'critical', confidence: 'high', category: 'exfiltration',
    description: 'The file reads secret-bearing state and also performs an outbound network operation.', patterns: [],
    remediation: 'Separate secret access from networking and allow-list a trusted destination with explicit field-level redaction.',
    owner: 'core-security', reviewDate: '2026-08-01', limitations: 'This taint-lite rule does not prove that the same value reaches the sink.'
  };
  const finding = makeFinding(rule, path, content, network);
  const secretLoc = lineAndColumn(content, secret.index);
  finding.evidence.unshift({ path, line: secretLoc.line, column: secretLoc.column, excerpt: maskEvidence(secretLoc.sourceLine), redacted: true });
  return finding;
}

const PERMISSION_PATTERNS: Array<{ re: RegExp; resource: string; action: string; risk: Severity }> = [
  { re: /readFile|readFileSync|fs\.read|open\s*\([^,]+,\s*['\"]r|Get-Content|\bcat\s+/i, resource: 'filesystem', action: 'read', risk: 'low' },
  { re: /writeFile|appendFile|fs\.write|open\s*\([^,]+,\s*['\"][wa]|Set-Content|Add-Content/i, resource: 'filesystem', action: 'write', risk: 'medium' },
  { re: /unlink|rmSync|rmdir|Remove-Item|\brm\s+/i, resource: 'filesystem', action: 'delete', risk: 'high' },
  { re: /child_process|subprocess\.|os\.system|Start-Process|\b(?:bash|sh|pwsh|powershell)\b/i, resource: 'process', action: 'execute', risk: 'high' },
  { re: /process\.env|os\.(?:environ|getenv)|\$env:/i, resource: 'environment', action: 'read', risk: 'medium' },
  { re: /fetch\s*\(|axios\.|requests\.|curl\b|wget\b|Invoke-WebRequest/i, resource: 'network', action: 'connect', risk: 'medium' },
  { re: /postgres|mysql|mongodb|redis|sqlite/i, resource: 'database', action: 'connect', risk: 'medium' },
  { re: /playwright|puppeteer|selenium/i, resource: 'browser', action: 'automate', risk: 'medium' },
  { re: /sendMail|send_email|webhook|smtp|chat\.postMessage/i, resource: 'messaging', action: 'send', risk: 'high' },
  { re: /\bgit\s+(?:push|commit|clone)|simple-git/i, resource: 'git', action: 'modify', risk: 'medium' },
  { re: /(?:npm|pnpm|yarn|pip)\s+(?:add|install|exec|dlx)/i, resource: 'package-manager', action: 'install-or-execute', risk: 'high' }
];

function mapPermissions(path: string, content: string): Permission[] {
  const result: Permission[] = [];
  for (const pattern of PERMISSION_PATTERNS) {
    const match = pattern.re.exec(content);
    if (!match) continue;
    const location = lineAndColumn(content, match.index);
    result.push({
      resource: pattern.resource, action: pattern.action, scope: inferScope(content, match.index), risk: pattern.risk,
      evidence: { path, line: location.line, column: location.column, excerpt: maskEvidence(location.sourceLine), redacted: false }
    });
  }
  return result;
}

function inferScope(content: string, index: number): string {
  const nearby = content.slice(Math.max(0, index - 100), index + 250);
  const urls = nearby.match(/https?:\/\/[^\s'"`)]+/g);
  if (urls?.length) return urls.map((url) => { try { return new URL(url).host; } catch { return url; } }).join(',');
  if (/(?:\$HOME|process\.env\.HOME|~\/|['\"]\/['\"]|[A-Z]:\\)/i.test(nearby)) return 'broad';
  return 'unspecified';
}

function validateStructured(path: string, content: string): string | undefined {
  const extension = extname(path).toLowerCase();
  try {
    if (extension === '.json') JSON.parse(content);
    if (extension === '.yaml' || extension === '.yml') YAML.parse(content);
  } catch (error) { return String(error); }
  return;
}

function incompleteFinding(path: string, error: string): Finding {
  return {
    id: fingerprint('AS-SC-900', path, error), ruleId: 'AS-SC-900', title: 'Incomplete analysis',
    description: 'The file could not be fully parsed, so the scan may have missed behavior.', severity: 'medium', confidence: 'high', category: 'parser',
    evidence: [{ path, line: 1, column: 1, excerpt: maskEvidence(error), redacted: false }],
    remediation: 'Correct the syntax or use a supported format, then scan again.', status: 'open', metadata: {}
  };
}

function dedupePermissions(items: Permission[]): Permission[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    const key = `${item.resource}:${item.action}:${item.scope}:${item.evidence.path}`;
    if (seen.has(key)) return false;
    seen.add(key); return true;
  });
}

function calculateDimensions(findings: Finding[], permissions: Permission[]): RiskDimensions {
  const score = (categories: string[]) => findings.reduce((max, finding) =>
    categories.includes(finding.category) ? Math.max(max, [10, 25, 50, 75, 100][severityRank[finding.severity]] ?? 0) : max, 0);
  return {
    permission: Math.min(100, permissions.reduce((sum, item) => sum + severityRank[item.risk] * 8, 0)),
    execution: score(['execution', 'persistence', 'obfuscation']), exfiltration: score(['exfiltration', 'network', 'external-service']),
    secret: score(['secrets', 'exfiltration']), supplyChain: score(['supply-chain', 'mcp']), memoryPoison: score(['prompt-injection'])
  };
}

function componentType(path: string, content: string): Component['type'] {
  if (/skill\.md$/i.test(path)) return 'skill';
  if (/mcp|modelcontextprotocol/i.test(path) || /["']mcpServers?["']/.test(content)) return 'mcp-server';
  if (['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.py', '.sh', '.bash', '.zsh', '.ps1'].includes(extname(path).toLowerCase())) return 'script';
  if (['.json', '.yaml', '.yml', '.toml'].includes(extname(path).toLowerCase())) return 'config';
  return 'unknown';
}

export async function scanTarget(target: string, options: ScanOptions = {}): Promise<ScanReport> {
  const startedAt = new Date().toISOString();
  const { files, errors } = await discover(target, options.maxFileBytes ?? MAX_FILE_BYTES);
  let findings: Finding[] = [];
  let permissions: Permission[] = [];
  const components: Component[] = [];
  for (const file of files) {
    let content: string;
    try { content = await readFile(file.absolute, 'utf8'); }
    catch (error) { errors.push(`${file.relative}: ${String(error)}`); findings.push(incompleteFinding(file.relative, String(error))); continue; }
    findings.push(...scanRules(file.relative, content));
    const chain = secretNetworkChain(file.relative, content);
    if (chain) findings.push(chain);
    permissions.push(...mapPermissions(file.relative, content));
    const parseError = validateStructured(file.relative, content);
    if (parseError) { errors.push(`${file.relative}: ${parseError}`); findings.push(incompleteFinding(file.relative, parseError)); }
    components.push({
      id: sha256(file.relative).slice(0, 31), type: componentType(file.relative, content), name: basename(file.relative),
      hash: sha256(content), source: file.relative, signatureStatus: 'unknown'
    });
  }
  permissions = dedupePermissions(permissions);
  const now = Date.now();
  if (options.baseline) {
    const valid = new Set(options.baseline.suppressions.filter((item) => Date.parse(item.expiresAt) > now && item.owner && item.reason).map((item) => item.fingerprint));
    findings = findings.map((finding) => valid.has(finding.id) ? { ...finding, status: 'suppressed' as const } : finding);
  }
  findings.sort((a, b) => severityRank[b.severity] - severityRank[a.severity] || a.ruleId.localeCompare(b.ruleId));
  const risk = calculateDimensions(findings.filter((item) => item.status !== 'suppressed'), permissions);
  const report: ScanReport = {
    schemaVersion: SCHEMA_VERSION, scanId: createId('scan'), scannerVersion: VERSION, rulepackVersion: '2026.08.1',
    target: resolve(target), startedAt, completedAt: new Date().toISOString(), status: errors.length ? 'partial' : 'completed',
    filesScanned: files.length, bytesScanned: files.reduce((sum, file) => sum + file.size, 0), components, permissions, findings,
    risk, overallRisk: findings.some((item) => item.severity === 'critical' && item.status === 'open') ? 100 : calculateOverallRisk(risk),
    errors: errors.map(redactSecrets)
  };
  return scanReportSchema.parse(report);
}

export async function loadBaseline(path: string): Promise<Baseline> {
  const value = JSON.parse(await readFile(path, 'utf8')) as Baseline;
  if (value.version !== 1 || !Array.isArray(value.suppressions)) throw new Error('Invalid baseline format');
  return value;
}

export interface ScanDiff {
  added: Finding[]; removed: Finding[]; unchanged: number; riskDelta: number;
}

export function diffReports(oldReport: ScanReport, newReport: ScanReport): ScanDiff {
  const oldById = new Map(oldReport.findings.map((item) => [item.id, item]));
  const nextById = new Map(newReport.findings.map((item) => [item.id, item]));
  return {
    added: newReport.findings.filter((item) => !oldById.has(item.id)),
    removed: oldReport.findings.filter((item) => !nextById.has(item.id)),
    unchanged: newReport.findings.filter((item) => oldById.has(item.id)).length,
    riskDelta: Math.round((newReport.overallRisk - oldReport.overallRisk) * 10) / 10
  };
}
