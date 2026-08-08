import { posix } from 'node:path';
import YAML from 'yaml';
import { parse as parseToml } from 'smol-toml';
import { normalizeByteOrderMark } from '@agentshield/parsers';
import type { ComponentProvenance } from '@agentshield/core';

/** A manifest or lockfile candidate discovered by the scanner, keyed by its report-relative path. */
export interface ProvenanceInput {
  path: string;
  content: string;
}

interface ManifestRecord {
  directory: string;
  provenance: ComponentProvenance;
}

export interface ProvenanceIndex {
  manifests: ManifestRecord[];
  errors: string[];
}

const MANIFEST_NAMES = new Set(['package.json', 'pyproject.toml']);
const LOCKFILE_NAMES = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'pnpm-lock.yml']);

/** Recognises files worth parsing for supply-chain provenance. */
export function isProvenanceFile(relativePath: string): boolean {
  const name = posix.basename(normalize(relativePath));
  return MANIFEST_NAMES.has(name) || LOCKFILE_NAMES.has(name);
}

function normalize(relativePath: string): string {
  return relativePath.replaceAll('\\', '/');
}

/** Strips the `archive.zip!/` prefix so archive entries group by their in-archive directory. */
function directoryOf(relativePath: string): string {
  const normalized = normalize(relativePath);
  const directory = normalized.includes('/') ? normalized.slice(0, normalized.lastIndexOf('/')) : '';
  return directory;
}

function isPinnedSpecifier(specifier: string): boolean {
  const value = specifier.trim();
  if (!value) return false;
  if (/^(?:\d+\.\d+\.\d+)(?:[-+][0-9A-Za-z.-]+)?$/.test(value)) return true;
  if (/^==\s*\d+\.\d+/.test(value)) return true;
  return false;
}

function isRemoteSpecifier(specifier: string): boolean {
  return /^(?:git|git\+|https?:|file:|link:|portal:|github:|gitlab:|bitbucket:|ssh:)/i.test(specifier.trim());
}

function stringField(source: Record<string, unknown>, key: string): string | undefined {
  const value = source[key];
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function repositoryUrl(value: unknown): string | undefined {
  if (typeof value === 'string') return value.trim() || undefined;
  if (value && typeof value === 'object') {
    const url = (value as Record<string, unknown>).url;
    if (typeof url === 'string') return url.trim() || undefined;
  }
  return undefined;
}

function classifyDependencies(
  dependencies: Record<string, unknown> | undefined,
  unpinned: Set<string>,
  remote: Set<string>
): void {
  for (const [name, specifier] of Object.entries(dependencies ?? {})) {
    if (typeof specifier !== 'string') continue;
    if (isRemoteSpecifier(specifier)) { remote.add(`${name}@${specifier}`); continue; }
    if (!isPinnedSpecifier(specifier)) unpinned.add(`${name}@${specifier}`);
  }
}

function parsePackageManifest(path: string, content: string): ComponentProvenance {
  const parsed = JSON.parse(normalizeByteOrderMark(content)) as Record<string, unknown>;
  const unpinned = new Set<string>();
  const remote = new Set<string>();
  for (const key of ['dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies']) {
    classifyDependencies(parsed[key] as Record<string, unknown> | undefined, unpinned, remote);
  }
  return {
    packageName: stringField(parsed, 'name'),
    declaredVersion: stringField(parsed, 'version'),
    repositoryUrl: repositoryUrl(parsed.repository),
    homepageUrl: stringField(parsed, 'homepage'),
    manifest: normalize(path),
    unpinnedDependencies: [...unpinned].sort(),
    remoteDependencies: [...remote].sort()
  };
}

function parsePyprojectManifest(path: string, content: string): ComponentProvenance {
  const parsed = parseToml(normalizeByteOrderMark(content)) as Record<string, unknown>;
  const project = (parsed.project ?? {}) as Record<string, unknown>;
  const poetry = (((parsed.tool ?? {}) as Record<string, unknown>).poetry ?? {}) as Record<string, unknown>;
  const unpinned = new Set<string>();
  const remote = new Set<string>();

  const projectDependencies = Array.isArray(project.dependencies) ? project.dependencies : [];
  for (const entry of projectDependencies) {
    if (typeof entry !== 'string') continue;
    const [name = entry] = entry.split(/[<>=!~\s[]/, 1);
    const specifier = entry.slice(name.length).trim();
    if (isRemoteSpecifier(specifier.replace(/^@\s*/, ''))) { remote.add(entry); continue; }
    if (!isPinnedSpecifier(specifier)) unpinned.add(entry);
  }
  classifyDependencies(poetry.dependencies as Record<string, unknown> | undefined, unpinned, remote);

  const urls = (project.urls ?? {}) as Record<string, unknown>;
  return {
    packageName: stringField(project, 'name') ?? stringField(poetry, 'name'),
    declaredVersion: stringField(project, 'version') ?? stringField(poetry, 'version'),
    repositoryUrl: stringField(urls, 'Repository') ?? stringField(urls, 'Source') ?? stringField(poetry, 'repository'),
    homepageUrl: stringField(urls, 'Homepage') ?? stringField(poetry, 'homepage'),
    manifest: normalize(path),
    unpinnedDependencies: [...unpinned].sort(),
    remoteDependencies: [...remote].sort()
  };
}

interface LockResolution {
  resolvedVersion?: string;
  integrity?: string;
  registryUrl?: string;
}

function parseNpmLock(content: string): Map<string, LockResolution> {
  const resolutions = new Map<string, LockResolution>();
  const parsed = JSON.parse(normalizeByteOrderMark(content)) as Record<string, unknown>;
  const rootName = stringField(parsed, 'name');
  const packages = parsed.packages as Record<string, unknown> | undefined;
  for (const [key, value] of Object.entries(packages ?? {})) {
    if (!value || typeof value !== 'object') continue;
    const entry = value as Record<string, unknown>;
    const name = key === '' ? (stringField(entry, 'name') ?? rootName) : key.split('node_modules/').at(-1);
    if (!name) continue;
    resolutions.set(name, {
      resolvedVersion: stringField(entry, 'version'),
      integrity: stringField(entry, 'integrity'),
      registryUrl: stringField(entry, 'resolved')
    });
  }
  const legacy = parsed.dependencies as Record<string, unknown> | undefined;
  for (const [name, value] of Object.entries(legacy ?? {})) {
    if (resolutions.has(name) || !value || typeof value !== 'object') continue;
    const entry = value as Record<string, unknown>;
    resolutions.set(name, {
      resolvedVersion: stringField(entry, 'version'),
      integrity: stringField(entry, 'integrity'),
      registryUrl: stringField(entry, 'resolved')
    });
  }
  return resolutions;
}

function parsePnpmLock(content: string): Map<string, LockResolution> {
  const resolutions = new Map<string, LockResolution>();
  const document = YAML.parse(normalizeByteOrderMark(content)) as Record<string, unknown> | null;
  const packages = (document?.packages ?? {}) as Record<string, unknown>;
  for (const [key, value] of Object.entries(packages)) {
    if (!value || typeof value !== 'object') continue;
    const entry = value as Record<string, unknown>;
    const resolution = (entry.resolution ?? {}) as Record<string, unknown>;
    // Keys look like `/name@1.2.3` or `name@1.2.3(peer@1.0.0)`.
    const stripped = key.replace(/^\//, '').replace(/\(.*\)$/, '');
    const separator = stripped.lastIndexOf('@');
    if (separator <= 0) continue;
    const name = stripped.slice(0, separator);
    resolutions.set(name, {
      resolvedVersion: stripped.slice(separator + 1) || undefined,
      integrity: stringField(resolution, 'integrity'),
      registryUrl: stringField(resolution, 'tarball')
    });
  }
  return resolutions;
}

/**
 * Builds a directory-keyed provenance index from discovered manifests and lockfiles.
 *
 * Parse failures are collected rather than thrown so a malformed manifest degrades provenance for
 * one component instead of aborting the scan.
 */
export function buildProvenanceIndex(inputs: ProvenanceInput[]): ProvenanceIndex {
  const manifests: ManifestRecord[] = [];
  const locks = new Map<string, { path: string; resolutions: Map<string, LockResolution> }>();
  const errors: string[] = [];

  for (const input of inputs) {
    const name = posix.basename(normalize(input.path));
    if (!LOCKFILE_NAMES.has(name)) continue;
    try {
      const resolutions = name.startsWith('pnpm-lock') ? parsePnpmLock(input.content) : parseNpmLock(input.content);
      locks.set(directoryOf(input.path), { path: normalize(input.path), resolutions });
    } catch (error) {
      errors.push(`${normalize(input.path)}: unreadable lockfile (${message(error)})`);
    }
  }

  for (const input of inputs) {
    const name = posix.basename(normalize(input.path));
    if (!MANIFEST_NAMES.has(name)) continue;
    try {
      const provenance = name === 'package.json'
        ? parsePackageManifest(input.path, input.content)
        : parsePyprojectManifest(input.path, input.content);
      const directory = directoryOf(input.path);
      const lock = locks.get(directory);
      if (lock) {
        provenance.lockfile = lock.path;
        const resolution = provenance.packageName ? lock.resolutions.get(provenance.packageName) : undefined;
        provenance.resolvedVersion = resolution?.resolvedVersion;
        provenance.integrity = resolution?.integrity;
        provenance.registryUrl = resolution?.registryUrl;
      }
      provenance.pinned = Boolean(provenance.lockfile)
        && provenance.unpinnedDependencies.length === 0
        && provenance.remoteDependencies.length === 0;
      manifests.push({ directory, provenance });
    } catch (error) {
      errors.push(`${normalize(input.path)}: unreadable manifest (${message(error)})`);
    }
  }

  // Deepest directory first so the nearest manifest wins for a nested file.
  manifests.sort((a, b) => b.directory.length - a.directory.length || a.directory.localeCompare(b.directory));
  return { manifests, errors };
}

/** Returns the nearest enclosing manifest provenance for a scanned file, if any was discovered. */
export function provenanceForPath(index: ProvenanceIndex, relativePath: string): ComponentProvenance | undefined {
  const directory = directoryOf(relativePath);
  for (const record of index.manifests) {
    if (record.directory === directory) return record.provenance;
    if (record.directory === '' || directory.startsWith(`${record.directory}/`)) return record.provenance;
  }
  return undefined;
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
