import { createHash, generateKeyPairSync, sign, verify } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { staticRules, type StaticRule } from '@agentshield/scanner';

/**
 * Signed rulepack format.
 *
 * A rulepack bundle is a single JSON file containing a deterministic manifest, the serialized rule
 * set, and an ed25519 signature over the canonical manifest. Signature verification proves the
 * publisher, and the manifest digest binds the rules to that signature, so neither the signature nor
 * the rule content can be replaced independently. Installed bundles are recorded in a local state
 * file that supports update and rollback without trusting the filesystem.
 */

export const RULEPACK_SCHEMA_VERSION = 1;
export const DEFAULT_STORE_DIR = '.agentshield';

export interface RulepackManifest {
  id: string;
  version: string;
  publisher: string;
  publishedAt: string;
  ruleCount: number;
  rulesSha256: string;
  signatureAlgorithm: 'ed25519';
}

/** A rule as stored inside a bundle: regex `patterns` carry their source and flags. */
export interface SerializedRule {
  id: string;
  title: string;
  description: string;
  severity: StaticRule['severity'];
  confidence: StaticRule['confidence'];
  category: string;
  patterns: Array<{ source: string; flags: string }>;
  remediation: string;
  owner: string;
  reviewDate: string;
  limitations: string;
}

export interface RulepackBundle {
  schemaVersion: number;
  manifest: RulepackManifest;
  rules: SerializedRule[];
  signature: string;
}

export interface RulepackVerification {
  valid: boolean;
  reasons: string[];
  manifest?: RulepackManifest;
}

export interface RulepackKeyPair {
  privateKeyPem: string;
  publicKeyPem: string;
}

export interface InstalledRulepack {
  version: string;
  publisher: string;
  installedAt: string;
  sourceHash: string;
}

export interface RulepackState {
  schemaVersion: number;
  current: string;
  installed: InstalledRulepack[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

/** Deterministic canonical form of the manifest; the bytes that are signed. */
export function canonicalManifestJson(manifest: RulepackManifest): string {
  return JSON.stringify({
    id: manifest.id,
    version: manifest.version,
    publisher: manifest.publisher,
    publishedAt: manifest.publishedAt,
    ruleCount: manifest.ruleCount,
    rulesSha256: manifest.rulesSha256,
    signatureAlgorithm: manifest.signatureAlgorithm
  });
}

/** Canonical serialized form of a rule set, sorted by rule id with regex sources and flags. */
function serializeRules(rules: StaticRule[]): SerializedRule[] {
  return [...rules]
    .sort((a, b) => a.id.localeCompare(b.id))
    .map((rule) => ({
      id: rule.id,
      title: rule.title,
      description: rule.description,
      severity: rule.severity,
      confidence: rule.confidence,
      category: rule.category,
      patterns: rule.patterns.map((pattern) => ({ source: pattern.source, flags: pattern.flags })),
      remediation: rule.remediation,
      owner: rule.owner,
      reviewDate: rule.reviewDate,
      limitations: rule.limitations
    }));
}

/** Deterministic digest input for a rule set in serialized or live form. */
function canonicalRulesJson(rules: unknown[]): string {
  const patternKey = (pattern: unknown): { source: string; flags: string } => {
    if (pattern instanceof RegExp) return { source: pattern.source, flags: pattern.flags };
    if (isRecord(pattern) && typeof pattern.source === 'string') {
      return { source: pattern.source, flags: typeof pattern.flags === 'string' ? pattern.flags : '' };
    }
    return { source: String(pattern), flags: '' };
  };
  const normalized = (item: unknown): Record<string, unknown> => {
    const rule = isRecord(item) ? item : {};
    return {
      id: String(rule.id ?? ''),
      title: String(rule.title ?? ''),
      description: String(rule.description ?? ''),
      severity: String(rule.severity ?? ''),
      confidence: String(rule.confidence ?? ''),
      category: String(rule.category ?? ''),
      patterns: Array.isArray(rule.patterns) ? rule.patterns.map(patternKey) : [],
      remediation: String(rule.remediation ?? ''),
      owner: String(rule.owner ?? ''),
      reviewDate: String(rule.reviewDate ?? ''),
      limitations: String(rule.limitations ?? '')
    };
  };
  const sorted = [...rules].sort((a, b) => {
    const aId = isRecord(a) ? String(a.id ?? '') : '';
    const bId = isRecord(b) ? String(b.id ?? '') : '';
    return aId.localeCompare(bId);
  });
  return JSON.stringify(sorted.map(normalized));
}

/** Restores `StaticRule` objects (including regex source and flags) from a serialized rule array. */
export function deserializeRules(serialized: unknown): StaticRule[] {
  if (!Array.isArray(serialized)) throw new Error('Rulepack contains no rules array');
  return serialized.map((item) => {
    if (!isRecord(item) || typeof item.id !== 'string') throw new Error('Rulepack contains an invalid rule');
    const restorePattern = (pattern: unknown): RegExp => {
      if (typeof pattern === 'string') return new RegExp(pattern);
      if (isRecord(pattern) && typeof pattern.source === 'string') {
        return new RegExp(pattern.source, typeof pattern.flags === 'string' ? pattern.flags : '');
      }
      return new RegExp(String(pattern));
    };
    return {
      id: item.id,
      title: String(item.title ?? ''),
      description: String(item.description ?? ''),
      severity: item.severity as StaticRule['severity'],
      confidence: item.confidence as StaticRule['confidence'],
      category: String(item.category ?? ''),
      patterns: Array.isArray(item.patterns) ? item.patterns.map(restorePattern) : [],
      remediation: String(item.remediation ?? ''),
      owner: String(item.owner ?? ''),
      reviewDate: String(item.reviewDate ?? ''),
      limitations: String(item.limitations ?? '')
    };
  });
}

export function generateRulepackKeyPair(): RulepackKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    privateKeyPem: String(privateKey.export({ type: 'pkcs8', format: 'pem' })),
    publicKeyPem: String(publicKey.export({ type: 'spki', format: 'pem' }))
  };
}

export function signRulepack(manifest: RulepackManifest, privateKeyPem: string): string {
  // Ed25519 ignores the algorithm argument; null selects the key's algorithm.
  return sign(null, Buffer.from(canonicalManifestJson(manifest), 'utf8'), privateKeyPem).toString('base64');
}

export function verifyRulepack(bundle: unknown, publicKeyPem: string): RulepackVerification {
  const reasons: string[] = [];
  if (!isRecord(bundle)) return { valid: false, reasons: ['Rulepack is not an object'] };
  if (bundle.schemaVersion !== RULEPACK_SCHEMA_VERSION) reasons.push(`Unsupported rulepack schema version: ${String(bundle.schemaVersion)}`);
  if (!isRecord(bundle.manifest) || typeof bundle.signature !== 'string') reasons.push('Rulepack is missing its manifest or signature');
  if (!Array.isArray(bundle.rules)) reasons.push('Rulepack is missing its rules array');
  if (reasons.length) return { valid: false, reasons };
  const manifest = bundle.manifest as RulepackManifest;
  const signature = bundle.signature as string;
  const rules = bundle.rules as unknown[];
  let signatureValid = false;
  try {
    signatureValid = verify(null, Buffer.from(canonicalManifestJson(manifest), 'utf8'), publicKeyPem, Buffer.from(signature, 'base64'));
  } catch { signatureValid = false; }
  if (!signatureValid) reasons.push('Signature does not verify against the supplied publisher key');
  if (rules.length !== manifest.ruleCount) reasons.push('Rule count does not match the manifest');
  const digest = createHash('sha256').update(canonicalRulesJson(rules)).digest('hex');
  if (digest !== manifest.rulesSha256) reasons.push('Rules content does not match the manifest digest');
  return { valid: reasons.length === 0, reasons, manifest };
}

export function buildRulepack(options: {
  version: string;
  publisher: string;
  privateKeyPem: string;
  rules?: StaticRule[];
  id?: string;
  publishedAt?: string;
}): RulepackBundle {
  if (!options.version || !options.publisher) throw new Error('A rulepack requires a version and a publisher');
  const rules = [...(options.rules ?? staticRules)].sort((a, b) => a.id.localeCompare(b.id));
  const serialized = serializeRules(rules);
  const manifest: RulepackManifest = {
    id: options.id ?? 'agentshield-rulepack',
    version: options.version,
    publisher: options.publisher,
    publishedAt: options.publishedAt ?? new Date().toISOString(),
    ruleCount: serialized.length,
    rulesSha256: createHash('sha256').update(canonicalRulesJson(serialized)).digest('hex'),
    signatureAlgorithm: 'ed25519'
  };
  return { schemaVersion: RULEPACK_SCHEMA_VERSION, manifest, rules: serialized, signature: signRulepack(manifest, options.privateKeyPem) };
}

export async function loadRulepackBundle(path: string): Promise<RulepackBundle> {
  const parsed = JSON.parse(await readFile(path, 'utf8')) as unknown;
  if (!isRecord(parsed)) throw new Error('Rulepack file is not a JSON object');
  return parsed as unknown as RulepackBundle;
}

export function compareVersions(a: string, b: string): number {
  const numbers = (value: string): number[] => value.split('.').map((part) => {
    const match = /^(\d+)/.exec(part);
    return match ? Number(match[1]) : 0;
  });
  const left = numbers(a);
  const right = numbers(b);
  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index++) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference) return difference;
  }
  return 0;
}

function statePath(storeDir: string): string {
  return join(storeDir, 'rulepacks.json');
}

function bundlePath(storeDir: string, version: string): string {
  const safe = version.replace(/[^A-Za-z0-9._-]/g, '_');
  return join(storeDir, 'rulepacks', `${safe}.rulepack.json`);
}

export async function loadRulepackState(storeDir = DEFAULT_STORE_DIR): Promise<RulepackState> {
  try {
    const parsed = JSON.parse(await readFile(statePath(storeDir), 'utf8')) as unknown;
    if (isRecord(parsed) && Array.isArray(parsed.installed)) {
      const state: RulepackState = {
        schemaVersion: 1,
        current: typeof parsed.current === 'string' ? parsed.current : '',
        installed: (parsed.installed as unknown[]).filter(isRecord).map((item) => ({
          version: String(item.version ?? ''),
          publisher: String(item.publisher ?? ''),
          installedAt: String(item.installedAt ?? ''),
          sourceHash: String(item.sourceHash ?? '')
        }))
      };
      sortInstalled(state);
      return state;
    }
  } catch { /* first run */ }
  return { schemaVersion: 1, current: '', installed: [] };
}

function sortInstalled(state: RulepackState): void {
  state.installed.sort((a, b) => compareVersions(a.version, b.version));
}

async function saveRulepackState(storeDir: string, state: RulepackState): Promise<void> {
  await mkdir(storeDir, { recursive: true });
  await writeFile(statePath(storeDir), `${JSON.stringify(state, null, 2)}\n`, 'utf8');
}

/**
 * Verifies a bundle against the publisher key and, on success, records it as the current rulepack.
 * A rejected bundle never touches the state file.
 */
export async function installRulepack(
  bundle: RulepackBundle,
  publicKeyPem: string,
  storeDir = DEFAULT_STORE_DIR
): Promise<{ verification: RulepackVerification; state: RulepackState; bundlePath?: string }> {
  const verification = verifyRulepack(bundle, publicKeyPem);
  const state = await loadRulepackState(storeDir);
  if (!verification.valid) return { verification, state };
  await mkdir(join(storeDir, 'rulepacks'), { recursive: true });
  const path = bundlePath(storeDir, bundle.manifest.version);
  await writeFile(path, `${JSON.stringify(bundle, null, 2)}\n`, 'utf8');
  const record: InstalledRulepack = {
    version: bundle.manifest.version,
    publisher: bundle.manifest.publisher,
    installedAt: new Date().toISOString(),
    sourceHash: createHash('sha256').update(JSON.stringify(bundle.rules)).digest('hex').slice(0, 16)
  };
  const existing = state.installed.find((item) => item.version === record.version);
  if (existing) Object.assign(existing, record);
  else state.installed.push(record);
  sortInstalled(state);
  state.current = record.version;
  await saveRulepackState(storeDir, state);
  return { verification, state, bundlePath: path };
}

/** Moves the active version to the highest installed version below the current one. */
export async function rollbackRulepack(storeDir = DEFAULT_STORE_DIR): Promise<{ state: RulepackState; previous?: string }> {
  const state = await loadRulepackState(storeDir);
  const currentIndex = state.installed.findIndex((item) => item.version === state.current);
  const previous = currentIndex > 0 ? state.installed[currentIndex - 1] : undefined;
  if (previous) state.current = previous.version;
  await saveRulepackState(storeDir, state);
  return { state, previous: previous?.version };
}

export async function loadCurrentRulepack(storeDir = DEFAULT_STORE_DIR): Promise<RulepackBundle | undefined> {
  const state = await loadRulepackState(storeDir);
  if (!state.current) return undefined;
  try { return await loadRulepackBundle(bundlePath(storeDir, state.current)); }
  catch { return undefined; }
}
