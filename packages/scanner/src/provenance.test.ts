import { describe, expect, it } from 'vitest';
import { buildProvenanceIndex, isProvenanceFile, provenanceForPath } from './provenance.js';

describe('provenance discovery', () => {
  it('recognises manifests and lockfiles only', () => {
    for (const path of ['package.json', 'skill/package.json', 'pyproject.toml', 'package-lock.json', 'pnpm-lock.yaml']) {
      expect(isProvenanceFile(path)).toBe(true);
    }
    for (const path of ['index.ts', 'SKILL.md', 'config.yaml', 'packages.json']) {
      expect(isProvenanceFile(path)).toBe(false);
    }
  });

  it('extracts npm package metadata, resolution, and integrity from a lockfile', () => {
    const index = buildProvenanceIndex([
      {
        path: 'package.json',
        content: JSON.stringify({
          name: 'demo-skill',
          version: '1.2.3',
          repository: { url: 'git+https://example.invalid/demo-skill.git' },
          homepage: 'https://example.invalid/demo',
          dependencies: { pinned: '1.0.0' }
        })
      },
      {
        path: 'package-lock.json',
        content: JSON.stringify({
          name: 'demo-skill',
          packages: {
            '': { name: 'demo-skill', version: '1.2.3' },
            'node_modules/pinned': {
              version: '1.0.0',
              integrity: 'sha512-abc',
              resolved: 'https://registry.example.invalid/pinned/-/pinned-1.0.0.tgz'
            }
          }
        })
      }
    ]);
    const provenance = provenanceForPath(index, 'index.ts');
    expect(index.errors).toEqual([]);
    expect(provenance).toMatchObject({
      packageName: 'demo-skill',
      declaredVersion: '1.2.3',
      resolvedVersion: '1.2.3',
      repositoryUrl: 'git+https://example.invalid/demo-skill.git',
      homepageUrl: 'https://example.invalid/demo',
      manifest: 'package.json',
      lockfile: 'package-lock.json',
      pinned: true,
      unpinnedDependencies: [],
      remoteDependencies: []
    });
  });

  it('flags unpinned ranges and remote dependency specifiers', () => {
    const index = buildProvenanceIndex([{
      path: 'package.json',
      content: JSON.stringify({
        name: 'loose-skill',
        dependencies: { ranged: '^2.0.0', tagged: 'latest', exact: '3.1.0' },
        devDependencies: { fromGit: 'git+https://example.invalid/pkg.git', fromUrl: 'https://example.invalid/pkg.tgz' }
      })
    }]);
    const provenance = provenanceForPath(index, 'src/tool.ts');
    expect(provenance?.unpinnedDependencies).toEqual(['ranged@^2.0.0', 'tagged@latest']);
    expect(provenance?.remoteDependencies).toEqual([
      'fromGit@git+https://example.invalid/pkg.git',
      'fromUrl@https://example.invalid/pkg.tgz'
    ]);
    expect(provenance?.pinned).toBe(false);
    expect(provenance?.lockfile).toBeUndefined();
  });

  it('reads pnpm lockfile resolutions', () => {
    const index = buildProvenanceIndex([
      { path: 'package.json', content: JSON.stringify({ name: 'pnpm-skill', version: '0.1.0' }) },
      {
        path: 'pnpm-lock.yaml',
        content: [
          'lockfileVersion: "9.0"',
          'packages:',
          '  /pnpm-skill@0.1.0:',
          '    resolution:',
          '      integrity: sha512-xyz',
          '      tarball: https://registry.example.invalid/pnpm-skill.tgz'
        ].join('\n')
      }
    ]);
    expect(provenanceForPath(index, 'index.ts')).toMatchObject({
      lockfile: 'pnpm-lock.yaml',
      resolvedVersion: '0.1.0',
      integrity: 'sha512-xyz',
      registryUrl: 'https://registry.example.invalid/pnpm-skill.tgz'
    });
  });

  it('extracts pyproject metadata and unpinned Python requirements', () => {
    const index = buildProvenanceIndex([{
      path: 'pyproject.toml',
      content: [
        '[project]',
        'name = "py-skill"',
        'version = "2.0.0"',
        'dependencies = ["requests>=2.0", "pinned==1.4.2"]',
        '',
        '[project.urls]',
        'Repository = "https://example.invalid/py-skill"'
      ].join('\n')
    }]);
    expect(provenanceForPath(index, 'tool.py')).toMatchObject({
      packageName: 'py-skill',
      declaredVersion: '2.0.0',
      repositoryUrl: 'https://example.invalid/py-skill',
      unpinnedDependencies: ['requests>=2.0']
    });
  });

  it('attributes a nested file to its closest manifest', () => {
    const index = buildProvenanceIndex([
      { path: 'package.json', content: JSON.stringify({ name: 'root' }) },
      { path: 'skills/inner/package.json', content: JSON.stringify({ name: 'inner' }) }
    ]);
    expect(provenanceForPath(index, 'skills/inner/src/tool.ts')?.packageName).toBe('inner');
    expect(provenanceForPath(index, 'src/tool.ts')?.packageName).toBe('root');
  });

  it('degrades to an error instead of throwing on malformed provenance files', () => {
    const index = buildProvenanceIndex([
      { path: 'package.json', content: '{"name": "broken",}' },
      { path: 'package-lock.json', content: 'not json at all' }
    ]);
    expect(index.manifests).toEqual([]);
    expect(index.errors.join('\n')).toContain('unreadable manifest');
    expect(index.errors.join('\n')).toContain('unreadable lockfile');
    expect(provenanceForPath(index, 'index.ts')).toBeUndefined();
  });
});
