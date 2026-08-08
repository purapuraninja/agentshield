import { Gunzip, strFromU8, unzipSync, type UnzipFileInfo } from 'fflate';

export type ArchiveFormat = 'zip' | 'tar' | 'tar.gz';

export interface ArchiveLimits {
  maxFiles: number;
  maxExpandedBytes: number;
  maxCompressionRatio: number;
  maxDepth: number;
  maxEntryNameBytes: number;
}

export interface ArchiveEntry {
  path: string;
  content: string;
  size: number;
}

export interface ArchiveInspection {
  format: ArchiveFormat;
  entries: ArchiveEntry[];
  errors: string[];
  expandedBytes: number;
  totalFiles: number;
}

export const DEFAULT_ARCHIVE_LIMITS: ArchiveLimits = {
  maxFiles: 1_000,
  maxExpandedBytes: 50 * 1024 * 1024,
  maxCompressionRatio: 100,
  maxDepth: 20,
  maxEntryNameBytes: 1_024
};

const TAR_BLOCK = 512;
const FORMAT_LABEL: Record<ArchiveFormat, string> = { zip: 'ZIP', tar: 'TAR', 'tar.gz': 'TAR.GZ' };

class ArchiveLimitError extends Error {}

/** Maps a scan target name to a supported archive container, or undefined for non-archives. */
export function archiveFormatForPath(path: string): ArchiveFormat | undefined {
  const lower = path.toLowerCase();
  if (lower.endsWith('.zip') || lower.endsWith('.whl')) return 'zip';
  if (lower.endsWith('.tar.gz') || lower.endsWith('.tgz')) return 'tar.gz';
  if (lower.endsWith('.tar')) return 'tar';
  return undefined;
}

function resolveLimits(overrides: Partial<ArchiveLimits>): ArchiveLimits {
  const limits = { ...DEFAULT_ARCHIVE_LIMITS, ...overrides };
  if (!Number.isInteger(limits.maxFiles) || limits.maxFiles < 1) throw new Error('Archive maxFiles must be a positive integer');
  if (!Number.isInteger(limits.maxExpandedBytes) || limits.maxExpandedBytes < 1) throw new Error('Archive maxExpandedBytes must be a positive integer');
  if (!Number.isFinite(limits.maxCompressionRatio) || limits.maxCompressionRatio < 1) throw new Error('Archive maxCompressionRatio must be at least 1');
  if (!Number.isInteger(limits.maxDepth) || limits.maxDepth < 1) throw new Error('Archive maxDepth must be a positive integer');
  if (!Number.isInteger(limits.maxEntryNameBytes) || limits.maxEntryNameBytes < 1) throw new Error('Archive maxEntryNameBytes must be a positive integer');
  return limits;
}

function safeEntryPath(name: string, limits: ArchiveLimits, label: string): string {
  if (!name || name.includes('\0')) throw new Error(`${label} entry has an empty or NUL-containing path`);
  if (Buffer.byteLength(name, 'utf8') > limits.maxEntryNameBytes) throw new Error(`${label} entry path exceeds the configured length limit`);
  const normalized = name.replaceAll('\\', '/').replace(/^\.\//, '');
  if (normalized.startsWith('/') || /^[A-Za-z]:\//.test(normalized)) throw new Error(`${label} entry uses an absolute path: ${name}`);
  const segments = normalized.split('/').filter(Boolean);
  if (segments.some((segment) => segment === '..')) throw new Error(`${label} entry attempts path traversal: ${name}`);
  if (segments.length > limits.maxDepth) throw new Error(`${label} entry exceeds the ${limits.maxDepth}-level depth limit: ${name}`);
  return segments.join('/');
}

/** Routes a compressed target to the matching inspector using one shared limit policy. */
export function inspectArchive(
  format: ArchiveFormat,
  compressed: Uint8Array,
  isSupported: (path: string) => boolean,
  maxFileBytes: number,
  overrides: Partial<ArchiveLimits> = {}
): ArchiveInspection {
  if (format === 'zip') return inspectZipArchive(compressed, isSupported, maxFileBytes, overrides);
  return inspectTarArchive(format, compressed, isSupported, maxFileBytes, overrides);
}

export function inspectZipArchive(
  compressed: Uint8Array,
  isSupported: (path: string) => boolean,
  maxFileBytes: number,
  overrides: Partial<ArchiveLimits> = {}
): ArchiveInspection {
  const limits = resolveLimits(overrides);
  const selected = new Set<string>();
  const allFiles = new Set<string>();
  const oversized: string[] = [];
  let totalFiles = 0;
  let expandedBytes = 0;

  const filter = (entry: UnzipFileInfo): boolean => {
    const path = safeEntryPath(entry.name, limits, 'ZIP');
    if (!path || entry.name.endsWith('/')) return false;
    if (allFiles.has(path)) throw new Error(`ZIP contains a duplicate entry path: ${path}`);
    allFiles.add(path);
    totalFiles++;
    if (totalFiles > limits.maxFiles) throw new Error(`ZIP exceeds the ${limits.maxFiles}-file limit`);
    expandedBytes += entry.originalSize;
    if (expandedBytes > limits.maxExpandedBytes) throw new Error(`ZIP exceeds the ${limits.maxExpandedBytes}-byte expanded-size limit`);
    const ratio = entry.originalSize / Math.max(1, entry.size);
    if (ratio > limits.maxCompressionRatio) throw new Error(`ZIP entry exceeds the ${limits.maxCompressionRatio}:1 compression-ratio limit: ${path}`);
    if (!isSupported(path)) return false;
    if (entry.originalSize > maxFileBytes) { oversized.push(path); return false; }
    selected.add(path);
    return true;
  };

  let unpacked: Record<string, Uint8Array>;
  try { unpacked = unzipSync(compressed, { filter }); }
  catch (error) { throw new Error(`Unsafe or malformed ZIP archive: ${String(error)}`); }
  const entries: ArchiveEntry[] = [];
  const errors = oversized.map((path) => `${path}: exceeds ${maxFileBytes} byte limit`);
  for (const [rawPath, bytes] of Object.entries(unpacked)) {
    const path = safeEntryPath(rawPath, limits, 'ZIP');
    if (!selected.has(path)) continue;
    if (bytes.byteLength > maxFileBytes) { errors.push(`${path}: expanded beyond ${maxFileBytes} byte limit`); continue; }
    try { entries.push({ path, content: strFromU8(bytes, true), size: bytes.byteLength }); }
    catch { errors.push(`${path}: content is not valid UTF-8 text`); }
  }
  entries.sort((a, b) => a.path.localeCompare(b.path));
  return { format: 'zip', entries, errors, expandedBytes, totalFiles };
}

/** Streams a gzip member with a hard output cap so a decompression bomb cannot exhaust memory. */
function gunzipWithinLimits(compressed: Uint8Array, limits: ArchiveLimits): Uint8Array {
  const chunks: Uint8Array[] = [];
  let total = 0;
  const stream = new Gunzip((chunk) => {
    total += chunk.byteLength;
    if (total > limits.maxExpandedBytes) {
      throw new ArchiveLimitError(`TAR.GZ stream exceeds the ${limits.maxExpandedBytes}-byte expanded-size limit`);
    }
    chunks.push(chunk);
  });
  try { stream.push(compressed, true); }
  catch (error) {
    if (error instanceof ArchiveLimitError) throw error;
    throw new Error(`Unsafe or malformed gzip member: ${String(error)}`);
  }
  const ratio = total / Math.max(1, compressed.byteLength);
  if (ratio > limits.maxCompressionRatio) {
    throw new ArchiveLimitError(`TAR.GZ stream exceeds the ${limits.maxCompressionRatio}:1 compression-ratio limit`);
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { output.set(chunk, offset); offset += chunk.byteLength; }
  return output;
}

function tarNumericField(block: Uint8Array, offset: number, length: number, field: string): number {
  const raw = block.subarray(offset, offset + length);
  const first = raw[0] ?? 0;
  if ((first & 0x80) !== 0) {
    let value = first & 0x7f;
    for (let index = 1; index < raw.length; index++) value = value * 256 + (raw[index] ?? 0);
    if (!Number.isSafeInteger(value)) throw new Error(`TAR header ${field} is outside the safe integer range`);
    return value;
  }
  let text = '';
  for (const byte of raw) { if (byte === 0) break; text += String.fromCharCode(byte); }
  text = text.trim();
  if (!text) return 0;
  if (!/^[0-7]+$/.test(text)) throw new Error(`TAR header ${field} is not a valid octal value`);
  const value = Number.parseInt(text, 8);
  if (!Number.isSafeInteger(value)) throw new Error(`TAR header ${field} is outside the safe integer range`);
  return value;
}

function verifyTarChecksum(block: Uint8Array): void {
  const declared = tarNumericField(block, 148, 8, 'checksum');
  let unsigned = 0;
  let signed = 0;
  for (let index = 0; index < TAR_BLOCK; index++) {
    const byte = index >= 148 && index < 156 ? 0x20 : block[index] ?? 0;
    unsigned += byte;
    signed += byte > 127 ? byte - 256 : byte;
  }
  if (declared !== unsigned && declared !== signed) throw new Error('TAR header checksum does not match its block');
}

function tarEntryName(block: Uint8Array): string {
  const read = (offset: number, length: number): string => {
    const raw = block.subarray(offset, offset + length);
    let text = '';
    for (const byte of raw) { if (byte === 0) break; text += String.fromCharCode(byte); }
    return text;
  };
  const name = read(0, 100);
  const isUstar = read(257, 5).startsWith('ustar');
  const prefix = isUstar ? read(345, 155) : '';
  return prefix ? `${prefix}/${name}` : name;
}

export function inspectTarArchive(
  format: 'tar' | 'tar.gz',
  compressed: Uint8Array,
  isSupported: (path: string) => boolean,
  maxFileBytes: number,
  overrides: Partial<ArchiveLimits> = {}
): ArchiveInspection {
  const limits = resolveLimits(overrides);
  const label = FORMAT_LABEL[format];
  const bytes = format === 'tar.gz' ? gunzipWithinLimits(compressed, limits) : compressed;
  if (format === 'tar' && bytes.byteLength > limits.maxExpandedBytes) {
    throw new Error(`TAR exceeds the ${limits.maxExpandedBytes}-byte expanded-size limit`);
  }

  const entries: ArchiveEntry[] = [];
  const errors: string[] = [];
  const seen = new Set<string>();
  let totalFiles = 0;
  let expandedBytes = 0;
  let offset = 0;
  let pendingLongName: string | undefined;
  let sawHeader = false;

  while (offset + TAR_BLOCK <= bytes.byteLength) {
    const block = bytes.subarray(offset, offset + TAR_BLOCK);
    if (block.every((byte) => byte === 0)) break;
    verifyTarChecksum(block);
    sawHeader = true;
    const size = tarNumericField(block, 124, 12, 'size');
    const typeFlag = String.fromCharCode(block[156] ?? 0);
    const rawName = pendingLongName ?? tarEntryName(block);
    pendingLongName = undefined;
    const dataOffset = offset + TAR_BLOCK;
    if (dataOffset + size > bytes.byteLength) throw new Error(`${label} entry data extends past the end of the archive`);
    offset = dataOffset + Math.ceil(size / TAR_BLOCK) * TAR_BLOCK;
    const data = () => bytes.subarray(dataOffset, dataOffset + size);

    if (typeFlag === 'L') {
      if (size > limits.maxEntryNameBytes) throw new Error(`${label} entry path exceeds the configured length limit`);
      pendingLongName = strFromU8(data(), true).replace(/\0+$/, '');
      continue;
    }
    if (typeFlag === 'K' || typeFlag === 'x' || typeFlag === 'g') continue;
    if (typeFlag === '1' || typeFlag === '2') throw new Error(`${label} entry uses a link that could escape the archive: ${rawName}`);
    if (typeFlag === '5') { safeEntryPath(rawName, limits, label); continue; }
    if (!['0', '7', '\0', ''].includes(typeFlag)) continue;

    const path = safeEntryPath(rawName, limits, label);
    if (seen.has(path)) throw new Error(`${label} contains a duplicate entry path: ${path}`);
    seen.add(path);
    totalFiles++;
    if (totalFiles > limits.maxFiles) throw new Error(`${label} exceeds the ${limits.maxFiles}-file limit`);
    expandedBytes += size;
    if (expandedBytes > limits.maxExpandedBytes) throw new Error(`${label} exceeds the ${limits.maxExpandedBytes}-byte expanded-size limit`);
    if (!isSupported(path)) continue;
    if (size > maxFileBytes) { errors.push(`${path}: exceeds ${maxFileBytes} byte limit`); continue; }
    try { entries.push({ path, content: strFromU8(data(), true), size }); }
    catch { errors.push(`${path}: content is not valid UTF-8 text`); }
  }

  if (!sawHeader) throw new Error(`Unsafe or malformed ${label} archive: no readable entry header was found`);
  entries.sort((a, b) => a.path.localeCompare(b.path));
  return { format, entries, errors, expandedBytes, totalFiles };
}
