import { lstat, readFile, readdir } from 'node:fs/promises';
import { basename, dirname, extname, join, relative, resolve } from 'node:path';
import ignore, { type Ignore } from 'ignore';
import {
  SCHEMA_VERSION, VERSION, calculateOverallRisk, createId, maskEvidence, normalizePath, redactSecrets,
  scanReportSchema, sha256, severityRank, type Component, type Finding, type Permission,
  type RiskDimensions, type ScanReport, type Severity
} from '@agentshield/core';
import { normalizeByteOrderMark, parseSource, type OperationKind, type ParsedFile, type SourceLocation, type ToolDefinition } from '@agentshield/parsers';
import { staticRules, type StaticRule } from './rules.js';
import { validateBaseline, type Baseline } from './baseline.js';
import { archiveFormatForPath, inspectArchive, type ArchiveLimits } from './archive.js';
import { buildProvenanceIndex, isProvenanceFile, provenanceForPath, type ProvenanceInput } from './provenance.js';

export { getRule, staticRules, type StaticRule } from './rules.js';
export {
  evaluatePolicy, loadPolicy, simulatePolicy, validatePolicy, type ExpressionTrace, type LegacyPolicyWhen,
  type PolicyEvaluation, type PolicyExpression, type PolicyField, type PolicyFile, type PolicyOperator,
  type PolicyPredicate, type PolicyRule, type PolicyRuleTrace
} from './policy.js';
export {
  addBaselineSuppressions, createBaseline, loadBaseline, parseBaseline, pruneExpiredSuppressions,
  saveBaseline, validateBaseline, type Baseline, type BaselineSelection, type BaselineSuppression,
  type BaselineValidation
} from './baseline.js';
export {
  DEFAULT_ARCHIVE_LIMITS, archiveFormatForPath, inspectArchive, inspectTarArchive, inspectZipArchive,
  type ArchiveFormat, type ArchiveInspection, type ArchiveLimits
} from './archive.js';
export {
  buildProvenanceIndex, isProvenanceFile, provenanceForPath,
  type ProvenanceIndex, type ProvenanceInput
} from './provenance.js';
export {
  activatePolicyVersion, approvePolicyException, evaluatePolicyWithExceptions, listPolicyExceptions,
  listPolicyVersions, loadStoredPolicy, publishPolicyVersion, readPolicyStore, rejectPolicyException,
  requestPolicyException, rollbackPolicyVersion,
  type PolicyException, type PolicyExceptionStatus, type PolicyExceptionTarget, type PolicySimulationSummary,
  type PolicyStoreFile, type PolicyVersion, type PolicyVersionState
} from './policy-store.js';

const SUPPORTED_EXTENSIONS = new Set([
  '.md', '.mdx', '.json', '.jsonl', '.yaml', '.yml', '.toml', '.js', '.mjs', '.cjs', '.ts', '.tsx',
  '.jsx', '.py', '.sh', '.bash', '.zsh', '.ps1', '.html', '.htm'
]);
const ALWAYS_IGNORED = ['.git/', 'node_modules/', 'dist/', 'build/', 'coverage/', '.agentshield/'];
const MAX_FILE_BYTES = 2 * 1024 * 1024;

interface DiscoveredFile { absolute: string; relative: string; size: number; content?: string }
export interface ScanOptions {
  baseline?: Baseline;
  maxFileBytes?: number;
  maxArchiveBytes?: number;
  archiveLimits?: Partial<ArchiveLimits>;
  /** Verified rulepack rules; defaults to the built-in deterministic rulepack. */
  rules?: StaticRule[];
}

async function buildIgnore(root: string): Promise<Ignore> {
  const matcher = ignore().add(ALWAYS_IGNORED);
  for (const name of ['.gitignore', '.agentshieldignore']) {
    try { matcher.add(await readFile(join(root, name), 'utf8')); } catch { /* optional */ }
  }
  return matcher;
}

async function discover(target: string, maxFileBytes: number, options: ScanOptions): Promise<{ files: DiscoveredFile[]; errors: string[] }> {
  const absoluteTarget = resolve(target);
  const targetStat = await lstat(absoluteTarget);
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
        const info = await lstat(absolute);
        if (info.size > maxFileBytes) errors.push(`${rel}: exceeds ${maxFileBytes} byte limit`);
        else files.push({ absolute, relative: rel || entry.name, size: info.size });
      }
    }
  }

  if (targetStat.isSymbolicLink()) errors.push(`${basename(absoluteTarget)}: symbolic link target rejected`);
  else if (targetStat.isFile()) {
    const targetName = basename(absoluteTarget);
    const archiveFormat = archiveFormatForPath(targetName);
    if (archiveFormat) {
      const maxArchiveBytes = options.maxArchiveBytes ?? 20 * 1024 * 1024;
      if (targetStat.size > maxArchiveBytes) errors.push(`${targetName}: exceeds ${maxArchiveBytes} byte archive limit`);
      else {
        try {
          const archive = inspectArchive(
            archiveFormat,
            await readFile(absoluteTarget),
            (path) => SUPPORTED_EXTENSIONS.has(extname(path).toLowerCase()) || /^skill\.md$/i.test(basename(path)),
            maxFileBytes,
            options.archiveLimits
          );
          files.push(...archive.entries.map((entry) => ({
            absolute: absoluteTarget,
            relative: `${targetName}!/${entry.path}`,
            size: entry.size,
            content: entry.content
          })));
          errors.push(...archive.errors.map((error) => `${targetName}!/${error}`));
          if (!archive.entries.length && !archive.errors.length) errors.push(`${targetName}: archive contains no supported source files`);
        } catch (error) { errors.push(`${targetName}: ${String(error)}`); }
      }
    }
    else if (!(SUPPORTED_EXTENSIONS.has(extname(targetName).toLowerCase()) || /^skill\.md$/i.test(targetName))) errors.push(`${targetName}: unsupported file format`);
    else if (targetStat.size <= maxFileBytes) files.push({ absolute: absoluteTarget, relative: targetName, size: targetStat.size });
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

function scanRules(path: string, content: string, rules: StaticRule[]): Finding[] {
  const extension = extname(path).toLowerCase();
  const findings: Finding[] = [];
  for (const rule of rules) {
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

function secretNetworkChain(path: string, content: string, parsed: ParsedFile): Finding | undefined {
  const flow = parsed.secretFlows[0];
  if (flow) {
    const sourceLine = content.split(/\r?\n/)[flow.source.line - 1] ?? flow.sourceName;
    const sinkLine = content.split(/\r?\n/)[flow.sink.line - 1] ?? flow.sinkName;
    const excerpt = maskEvidence(sinkLine);
    return {
      id: fingerprint('AS-SC-001', path, excerpt), ruleId: 'AS-SC-001', title: 'Secret-derived value reaches a network sink',
      description: 'AST data-flow analysis found an environment-derived value in an outbound network call.',
      severity: 'critical', confidence: 'high', category: 'exfiltration',
      evidence: [
        { path, line: flow.source.line, column: flow.source.column, excerpt: maskEvidence(sourceLine), redacted: true },
        { path, line: flow.sink.line, column: flow.sink.column, excerpt, redacted: true }
      ],
      remediation: 'Separate secret access from networking and allow-list a trusted destination with explicit field-level redaction.',
      status: 'open', metadata: { analysis: 'ast-data-flow', sourceName: flow.sourceName, sinkName: flow.sinkName, destination: flow.destination, through: flow.through }
    };
  }
  if (parsed.mode === 'ast' && !parsed.diagnostics.some((diagnostic) => diagnostic.severity === 'error')) return;
  const secret = /process\.env|os\.(?:environ|getenv)|\$env:|(?:API_KEY|TOKEN|SECRET|PASSWORD)/i.exec(content);
  const network = /fetch\s*\(|axios\.|requests\.|https?\.request|curl\b|Invoke-(?:WebRequest|RestMethod)/i.exec(content);
  if (!secret || !network) return;
  const rule: StaticRule = {
    id: 'AS-SC-001', title: 'Secret access and network sink in the same file', severity: 'critical', confidence: 'high', category: 'exfiltration',
    description: 'The file reads secret-bearing state and also performs an outbound network operation.', patterns: [],
    remediation: 'Separate secret access from networking and allow-list a trusted destination with explicit field-level redaction.',
    owner: 'core-security', reviewDate: '2026-08-01', limitations: 'Non-JS/TS fallback does not prove that the same value reaches the sink.'
  };
  const finding = makeFinding(rule, path, content, network);
  const secretLoc = lineAndColumn(content, secret.index);
  finding.evidence.unshift({ path, line: secretLoc.line, column: secretLoc.column, excerpt: maskEvidence(secretLoc.sourceLine), redacted: true });
  return finding;
}

function structuredToolFindings(path: string, content: string, parsed: ParsedFile): Finding[] {
  return parsed.tools.filter((tool) => tool.destructive && !tool.approvalDeclared).map((tool) => {
    const sourceLine = content.split(/\r?\n/)[tool.location.line - 1] ?? tool.name;
    const excerpt = maskEvidence(sourceLine);
    return {
      id: fingerprint('AS-SC-024', path, excerpt), ruleId: 'AS-SC-024', title: 'MCP tool has undeclared destructive side effects',
      description: `Structured tool definition “${tool.name}” suggests mutation or an external side effect without an approval declaration.`,
      severity: 'high' as const, confidence: 'high' as const, category: 'mcp',
      evidence: [{ path: normalizePath(path), line: tool.location.line, column: tool.location.column, excerpt, redacted: false }],
      remediation: 'Declare side effects explicitly and require confirmation or policy approval before execution.',
      status: 'open' as const, metadata: { analysis: 'structured-config', toolName: tool.name }
    };
  });
}

const DESTRUCTIVE_OPERATION_KINDS: ReadonlySet<OperationKind> = new Set([
  'filesystem.delete', 'filesystem.write', 'process.execute', 'messaging.send'
]);

interface MCPToolRecord {
  tool: ToolDefinition;
  configPath: string;
  content: string;
}

/** Resolves a handler reference to a path relative to the configuration file, when it is local. */
function resolveHandlerPath(handler: string, configPath: string): string | undefined {
  let candidate = handler.replace(/^\.\//, '').split(/[?#]/)[0]!;
  candidate = candidate.replaceAll('\\', '/');
  if (!candidate) return undefined;
  if (/^[A-Za-z][A-Za-z0-9+.-]*:/.test(candidate)) return undefined; // URLs and other schemes
  if (candidate.includes('node_modules/')) return undefined;
  const directory = configPath.includes('/') ? configPath.slice(0, configPath.lastIndexOf('/') + 1) : '';
  return normalizePath(directory + candidate);
}

function isReadOnlyDescription(description: string | undefined): boolean {
  if (!description) return false;
  const readOnly = /\b(?:read|get|list|search|lookup|fetch|query|inspect|retrieve|view|show|display|peek|find)\b/i.test(description);
  const destructive = /\b(?:delete|remove|drop|terminate|write|update|send|publish|create|execute|modify)\b/i.test(description);
  return readOnly && !destructive;
}

function readOnlyPermissions(permissions: string[] | undefined): boolean {
  if (!permissions || !permissions.length) return false;
  return permissions.every((permission) => /read|list|get|query|search|lookup/i.test(permission)) &&
    !permissions.some((permission) => /delete|write|update|execute|send|create|drop|remove|modify/i.test(permission));
}

/**
 * Compares declared tool side effects against the operations of the referenced handler. A tool that
 * declares read-only or narrowly scoped behavior but whose implementation performs destructive
 * operations is evidence of misleading MCP metadata, not just a misdeclared permission.
 */
function mcpImplementationFindings(
  records: MCPToolRecord[],
  scanned: Map<string, { parsed: ParsedFile; content: string }>
): Finding[] {
  const findings: Finding[] = [];
  for (const record of records) {
    const { tool, configPath, content } = record;
    if (!tool.handler) continue;
    const handlerPath = resolveHandlerPath(tool.handler, configPath);
    if (!handlerPath) continue;
    let target: { parsed: ParsedFile; content: string } | undefined;
    for (const [path, entry] of scanned) {
      const normalized = normalizePath(path);
      if (normalized === handlerPath || normalized.endsWith(`/${handlerPath}`)) { target = entry; break; }
    }
    if (!target) continue;
    const destructiveOps = target.parsed.operations.filter((operation) => DESTRUCTIVE_OPERATION_KINDS.has(operation.kind));
    if (!destructiveOps.length) continue;
    const declaredReadOnly = tool.readOnlyHint === true || isReadOnlyDescription(tool.description);
    const scopedReadOnly = readOnlyPermissions(tool.permissions);
    if (!declaredReadOnly && !scopedReadOnly) continue;
    const operationKinds = [...new Set(destructiveOps.map((operation) => operation.kind))];
    const sourceLine = content.split(/\r?\n/)[tool.location.line - 1] ?? tool.name;
    findings.push({
      id: fingerprint('AS-SC-027', configPath, `${tool.name}->${handlerPath}`),
      ruleId: 'AS-SC-027', title: 'MCP tool implementation exceeds declared read-only scope',
      description: `MCP tool “${tool.name}” declares read-only or narrowly scoped behavior, but its handler (${handlerPath}) performs destructive operations (${operationKinds.join(', ')}).`,
      severity: 'high' as const, confidence: 'high' as const, category: 'mcp',
      evidence: [
        { path: normalizePath(configPath), line: tool.location.line, column: tool.location.column, excerpt: maskEvidence(sourceLine), redacted: false },
        ...destructiveOps.slice(0, 3).map((operation) => {
          const line = target.content.split(/\r?\n/)[operation.location.line - 1] ?? operation.symbol;
          return { path: normalizePath(handlerPath), line: operation.location.line, column: operation.location.column, excerpt: maskEvidence(line), redacted: false };
        })
      ],
      remediation: 'Make the tool declaration match its implementation: keep read-only handlers free of destructive operations or declare the side effects and require policy approval.',
      status: 'open' as const, metadata: {
        analysis: 'mcp-declaration-vs-implementation', toolName: tool.name, handler: handlerPath,
        operations: operationKinds, permissionMismatch: scopedReadOnly && !declaredReadOnly
      }
    });
  }
  return findings;
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

const OPERATION_PERMISSIONS: Record<OperationKind, { resource: string; action: string; risk: Severity }> = {
  'environment.read': { resource: 'environment', action: 'read', risk: 'medium' },
  'filesystem.read': { resource: 'filesystem', action: 'read', risk: 'low' },
  'filesystem.write': { resource: 'filesystem', action: 'write', risk: 'medium' },
  'filesystem.delete': { resource: 'filesystem', action: 'delete', risk: 'high' },
  'network.connect': { resource: 'network', action: 'connect', risk: 'medium' },
  'process.execute': { resource: 'process', action: 'execute', risk: 'high' },
  'database.connect': { resource: 'database', action: 'connect', risk: 'medium' },
  'browser.automate': { resource: 'browser', action: 'automate', risk: 'medium' },
  'messaging.send': { resource: 'messaging', action: 'send', risk: 'high' },
  'git.modify': { resource: 'git', action: 'modify', risk: 'medium' },
  'package-manager.execute': { resource: 'package-manager', action: 'install-or-execute', risk: 'high' }
};

function evidenceAt(path: string, content: string, location: SourceLocation): Permission['evidence'] {
  const sourceLine = content.split(/\r?\n/)[location.line - 1] ?? '';
  const excerpt = maskEvidence(sourceLine);
  return { path, line: location.line, column: location.column, excerpt, redacted: excerpt.includes('[REDACTED:') };
}

function mapPermissions(path: string, content: string, parsed: ParsedFile): Permission[] {
  const result: Permission[] = [];
  for (const operation of parsed.operations) {
    const mapped = OPERATION_PERMISSIONS[operation.kind];
    result.push({ resource: mapped.resource, action: mapped.action, scope: operation.scope, risk: mapped.risk, evidence: evidenceAt(path, content, operation.location) });
  }
  if (parsed.mode === 'ast' && !parsed.diagnostics.some((diagnostic) => diagnostic.severity === 'error')) return result;
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

function incompleteFinding(path: string, error: string, location?: SourceLocation, code = 'PARSE_ERROR'): Finding {
  return {
    id: fingerprint('AS-SC-900', path, error), ruleId: 'AS-SC-900', title: 'Incomplete analysis',
    description: 'The file could not be fully parsed, so the scan may have missed behavior.', severity: 'medium', confidence: 'high', category: 'parser',
    evidence: [{ path, line: location?.line ?? 1, column: location?.column ?? 1, excerpt: maskEvidence(error), redacted: false }],
    remediation: 'Correct the syntax or use a supported format, then scan again.', status: 'open', metadata: { diagnosticCode: code }
  };
}

function analysisGapFinding(path: string, message: string, location: SourceLocation, code: string): Finding {
  return {
    id: fingerprint('AS-SC-901', path, message), ruleId: 'AS-SC-901', title: 'Conservative analysis fallback',
    description: 'This file was scanned without full AST-level data-flow analysis.', severity: 'low', confidence: 'high', category: 'parser',
    evidence: [{ path, line: location.line, column: location.column, excerpt: maskEvidence(message), redacted: false }],
    remediation: 'Review high-risk behavior manually or enable an AST-capable parser for this language.', status: 'open', metadata: { diagnosticCode: code }
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

function dedupeFindings(items: Finding[]): Finding[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    if (seen.has(item.id)) return false;
    seen.add(item.id);
    return true;
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
  const maxFileBytes = options.maxFileBytes ?? MAX_FILE_BYTES;
  const { files, errors } = await discover(target, maxFileBytes, options);

  // Manifests and lockfiles are read first so every scanned file can be attributed to its package.
  const provenanceInputs: ProvenanceInput[] = [];
  for (const file of files.filter((candidate) => isProvenanceFile(candidate.relative))) {
    try {
      const content = file.content ?? await readFile(file.absolute, 'utf8');
      provenanceInputs.push({ path: file.relative, content });
    } catch (error) { errors.push(`${file.relative}: ${String(error)}`); }
  }
  const provenanceIndex = buildProvenanceIndex(provenanceInputs);
  errors.push(...provenanceIndex.errors);

  let findings: Finding[] = errors.map((error) => incompleteFinding(error.split(':', 1)[0] || normalizePath(target), error, undefined, 'DISCOVERY_GAP'));
  let permissions: Permission[] = [];
  const components: Component[] = [];
  const scanned = new Map<string, { parsed: ParsedFile; content: string }>();
  const mcpTools: MCPToolRecord[] = [];
  for (const file of files) {
    let content: string;
    try {
      if (file.content !== undefined) content = file.content;
      else {
        const current = await lstat(file.absolute);
        if (current.isSymbolicLink()) throw new Error('symbolic link appeared after discovery');
        if (!current.isFile()) throw new Error('target is no longer a regular file');
        if (current.size > maxFileBytes) throw new Error(`file grew beyond ${maxFileBytes} byte limit`);
        content = await readFile(file.absolute, 'utf8');
      }
    }
    catch (error) { errors.push(`${file.relative}: ${String(error)}`); findings.push(incompleteFinding(file.relative, String(error))); continue; }
    // A leading BOM is legal and common. It is neutralized for analysis so it cannot be reported as a
    // hidden control character, while the component hash below still covers the real file content.
    const analyzed = normalizeByteOrderMark(content);
    const parsed = parseSource(file.relative, analyzed);
    scanned.set(file.relative, { parsed, content: analyzed });
    if (parsed.tools.length) {
      for (const tool of parsed.tools) mcpTools.push({ tool, configPath: file.relative, content: analyzed });
    }
    findings.push(...structuredToolFindings(file.relative, analyzed, parsed));
    findings.push(...scanRules(file.relative, analyzed, options.rules ?? staticRules));
    const chain = secretNetworkChain(file.relative, analyzed, parsed);
    if (chain) findings.push(chain);
    permissions.push(...mapPermissions(file.relative, analyzed, parsed));
    for (const diagnostic of parsed.diagnostics) {
      if (diagnostic.severity === 'error') {
        const message = `${file.relative}:${diagnostic.location.line}:${diagnostic.location.column} [${diagnostic.code}] ${diagnostic.message}`;
        errors.push(message);
        findings.push(incompleteFinding(file.relative, diagnostic.message, diagnostic.location, diagnostic.code));
      } else findings.push(analysisGapFinding(file.relative, diagnostic.message, diagnostic.location, diagnostic.code));
    }
    const provenance = provenanceForPath(provenanceIndex, file.relative);
    components.push({
      id: sha256(file.relative).slice(0, 31), type: componentType(file.relative, content), name: basename(file.relative),
      version: provenance?.resolvedVersion ?? provenance?.declaredVersion,
      hash: sha256(content), source: file.relative, signatureStatus: 'unknown',
      ...(provenance ? { provenance } : {})
    });
  }
  findings = dedupeFindings(findings);
  findings.push(...mcpImplementationFindings(mcpTools, scanned));
  findings = dedupeFindings(findings);
  permissions = dedupePermissions(permissions);
  const now = Date.now();
  if (options.baseline) {
    const validation = validateBaseline(options.baseline, new Date(now));
    if (!validation.valid) throw new Error(`Invalid baseline: ${validation.invalid.join('; ')}`);
    const valid = new Set(options.baseline.suppressions.filter((item) => Date.parse(item.expiresAt) > now && item.owner && item.reason).map((item) => item.fingerprint));
    findings = findings.map((finding) => valid.has(finding.id) ? { ...finding, status: 'suppressed' as const } : finding);
  }
  findings.sort((a, b) => severityRank[b.severity] - severityRank[a.severity] || a.ruleId.localeCompare(b.ruleId));
  const risk = calculateDimensions(findings.filter((item) => item.status !== 'suppressed'), permissions);
  const report: ScanReport = {
    schemaVersion: SCHEMA_VERSION, scanId: createId('scan'), scannerVersion: VERSION, rulepackVersion: '2026.08.2',
    target: resolve(target), startedAt, completedAt: new Date().toISOString(), status: errors.length ? 'partial' : 'completed',
    filesScanned: files.length, bytesScanned: files.reduce((sum, file) => sum + file.size, 0), components, permissions, findings,
    risk, overallRisk: findings.some((item) => item.severity === 'critical' && item.status === 'open') ? 100 : calculateOverallRisk(risk),
    errors: errors.map(redactSecrets)
  };
  return scanReportSchema.parse(report);
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
