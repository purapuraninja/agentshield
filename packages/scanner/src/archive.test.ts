import { gzipSync } from 'fflate';
import { describe, expect, it } from 'vitest';
import { archiveFormatForPath, inspectArchive, inspectTarArchive } from './archive.js';
import { TAR_BLOCK, buildTar } from './tar-fixture.js';

const supported = (path: string) => path.endsWith('.ts') || path.endsWith('.md');

describe('archive format routing', () => {
  it('maps supported container extensions and ignores everything else', () => {
    expect(archiveFormatForPath('extension.zip')).toBe('zip');
    expect(archiveFormatForPath('package-1.0.0-py3-none-any.whl')).toBe('zip');
    expect(archiveFormatForPath('package.tgz')).toBe('tar.gz');
    expect(archiveFormatForPath('package.TAR.GZ')).toBe('tar.gz');
    expect(archiveFormatForPath('bundle.tar')).toBe('tar');
    expect(archiveFormatForPath('notes.md')).toBeUndefined();
  });
});

describe('tar inspection', () => {
  it('reads supported entries from an npm-style tarball and skips other files', () => {
    const tar = buildTar([
      { name: 'package/index.ts', content: 'export const answer = 42;' },
      { name: 'package/logo.bin', content: 'binary-ish' },
      { name: 'package/', typeFlag: '5' }
    ]);
    const inspection = inspectArchive('tar.gz', gzipSync(tar), supported, 1024);
    expect(inspection.format).toBe('tar.gz');
    expect(inspection.entries.map((entry) => entry.path)).toEqual(['package/index.ts']);
    expect(inspection.entries[0]?.content).toContain('answer = 42');
    expect(inspection.totalFiles).toBe(2);
    expect(inspection.errors).toEqual([]);
  });

  it('supports GNU long names and ustar prefixed paths', () => {
    const longName = `package/${'nested/'.repeat(3)}deeply-named-module.ts`;
    const tar = buildTar([
      { name: '././@LongLink', content: `${longName}\0`, typeFlag: 'L' },
      { name: longName.slice(0, 100), content: 'export const value = 1;' }
    ]);
    const inspection = inspectTarArchive('tar', tar, supported, 1024);
    expect(inspection.entries.map((entry) => entry.path)).toEqual([longName]);
  });

  it('rejects path traversal and absolute entry paths', () => {
    for (const name of ['../escape.ts', '/etc/agent/escape.ts']) {
      expect(() => inspectTarArchive('tar', buildTar([{ name, content: 'x' }]), supported, 1024))
        .toThrow(/path traversal|absolute path/);
    }
  });

  it('rejects hard links and symlinks that could escape the archive', () => {
    for (const typeFlag of ['1', '2']) {
      expect(() => inspectTarArchive('tar', buildTar([{ name: 'package/link.ts', typeFlag }]), supported, 1024))
        .toThrow(/link that could escape/);
    }
  });

  it('enforces file-count and expanded-size limits', () => {
    const many = buildTar(Array.from({ length: 4 }, (_, index) => ({ name: `package/file${index}.ts`, content: 'x' })));
    expect(() => inspectTarArchive('tar', many, supported, 1024, { maxFiles: 2 })).toThrow(/2-file limit/);
    const large = buildTar([{ name: 'package/large.ts', content: 'A'.repeat(4096) }]);
    expect(() => inspectTarArchive('tar', large, supported, 8192, { maxExpandedBytes: 1024 })).toThrow(/expanded-size limit/);
  });

  it('enforces the gzip compression-ratio limit before parsing entries', () => {
    const bomb = gzipSync(buildTar([{ name: 'package/large.ts', content: 'A'.repeat(200_000) }]), { level: 9 });
    expect(() => inspectArchive('tar.gz', bomb, supported, 1_000_000, { maxCompressionRatio: 2 }))
      .toThrow(/compression-ratio limit/);
  });

  it('enforces the gzip expanded-size limit while streaming', () => {
    const bomb = gzipSync(buildTar([{ name: 'package/large.ts', content: 'A'.repeat(200_000) }]), { level: 9 });
    expect(() => inspectArchive('tar.gz', bomb, supported, 1_000_000, { maxExpandedBytes: 4096 }))
      .toThrow(/expanded-size limit/);
  });

  it('rejects duplicate entry paths', () => {
    const tar = buildTar([
      { name: 'package/index.ts', content: 'a' },
      { name: 'package/index.ts', content: 'b' }
    ]);
    expect(() => inspectTarArchive('tar', tar, supported, 1024)).toThrow(/duplicate entry path/);
  });

  it('rejects corrupt headers, malformed sizes, and truncated data', () => {
    expect(() => inspectTarArchive('tar', buildTar([{ name: 'package/a.ts', content: 'x', corruptChecksum: true }]), supported, 1024))
      .toThrow(/checksum does not match/);
    expect(() => inspectTarArchive('tar', buildTar([{ name: 'package/a.ts', content: 'x', declaredSize: 8192 }]), supported, 1024))
      .toThrow(/extends past the end/);
    expect(() => inspectTarArchive('tar', new Uint8Array(TAR_BLOCK).fill(0x41), supported, 1024))
      .toThrow(/checksum is not a valid octal value/);
    expect(() => inspectTarArchive('tar', new Uint8Array(8), supported, 1024))
      .toThrow(/no readable entry header/);
  });

  it('rejects malformed gzip members', () => {
    expect(() => inspectArchive('tar.gz', new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]), supported, 1024))
      .toThrow(/malformed gzip member/);
  });

  it('reports oversized supported entries without aborting the archive', () => {
    const tar = buildTar([
      { name: 'package/large.ts', content: 'A'.repeat(600) },
      { name: 'package/small.ts', content: 'export const ok = true;' }
    ]);
    const inspection = inspectTarArchive('tar', tar, supported, 128);
    expect(inspection.entries.map((entry) => entry.path)).toEqual(['package/small.ts']);
    expect(inspection.errors.join('\n')).toContain('exceeds 128 byte limit');
  });

  it('validates limit overrides', () => {
    expect(() => inspectTarArchive('tar', buildTar([{ name: 'a.ts', content: 'x' }]), supported, 1024, { maxFiles: 0 }))
      .toThrow(/maxFiles must be a positive integer/);
    expect(() => inspectTarArchive('tar', buildTar([{ name: 'a.ts', content: 'x' }]), supported, 1024, { maxDepth: 0 }))
      .toThrow(/maxDepth must be a positive integer/);
  });
});
