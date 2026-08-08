import { copyFile, mkdtemp, readFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { basename, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, it } from 'vitest';
import { auditMemory, listQuarantine, loadMemory, quarantineMemory } from '@agentshield/memory';
import { buildEvidenceGraph, evaluateRuntimePolicy, type RuntimePolicy } from '@agentshield/runtime';
import { scanTarget } from '@agentshield/scanner';

interface ThreatScenario {
  id: string;
  title: string;
  kind: 'scanner' | 'memory' | 'runtime' | 'quarantine' | 'memory-privacy';
  target: string;
  expect: string[];
  coverage?: 'detected' | 'gap';
  reason?: string;
}

interface ThreatManifest {
  version: number;
  language: string;
  scenarios: ThreatScenario[];
}

const THREATS_ROOT = resolve('fixtures/threats');
const manifest = JSON.parse(readFileSync(join(THREATS_ROOT, 'manifest.json'), 'utf8')) as ThreatManifest;

async function copyToTemp(relative: string): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'agentshield-threat-'));
  const source = join(THREATS_ROOT, relative);
  const target = join(directory, basename(relative));
  await copyFile(source, target);
  return target;
}

function firstId(record: { memoryId: string }): string {
  return record.memoryId;
}

describe('threat scenario corpus T-01..T-10', () => {
  it('covers every threat id from the plan', () => {
    const ids = manifest.scenarios.map((item) => item.id);
    for (let index = 1; index <= 10; index++) {
      const id = `T-${String(index).padStart(2, '0')}`;
      expect(ids, `missing scenario ${id}`).toContain(id);
    }
  });

  it('marks unmitigated controls explicitly instead of asserting false coverage', () => {
    const gaps = manifest.scenarios.filter((item) => item.coverage === 'gap');
    expect(gaps.length).toBeGreaterThan(0);
    for (const gap of gaps) {
      expect(gap.expect).toEqual([]);
      expect(gap.reason).toBeTruthy();
    }
  });

  it('provides multilingual instruction fixtures', () => {
    expect(manifest.language.toLowerCase()).toContain('indonesian');
    expect(manifest.language.toLowerCase()).toContain('english');
  });

  for (const scenario of manifest.scenarios) {
    if (scenario.coverage === 'gap') continue;
    it(`${scenario.id}: ${scenario.title}`, async () => {
      if (scenario.kind === 'scanner') {
        const report = await scanTarget(join(THREATS_ROOT, scenario.target));
        const found = new Set(report.findings.map((item) => item.ruleId));
        for (const ruleId of scenario.expect) expect(found, `missing ${ruleId}`).toContain(ruleId);
        return;
      }

      if (scenario.kind === 'memory' || scenario.kind === 'memory-privacy') {
        const target = await copyToTemp(scenario.target);
        const report = await auditMemory(target, { privacyMode: scenario.kind === 'memory-privacy' ? 'metadata-only' : 'pii-secrets' });
        const found = new Set(report.findings.map((item) => item.ruleId));
        for (const ruleId of scenario.expect.filter((item) => item !== 'redacted')) {
          expect(found, `missing ${ruleId}`).toContain(ruleId);
        }
        if (scenario.expect.includes('redacted')) {
          const raw = (await readFile(join(THREATS_ROOT, scenario.target), 'utf8'));
          const secret = raw.match(/sk-[A-Za-z0-9-]+/)?.[0];
          expect(secret).toBeTruthy();
          expect(JSON.stringify(report)).not.toContain(secret!);
        }
        return;
      }

      if (scenario.kind === 'quarantine') {
        const target = await copyToTemp(scenario.target);
        const records = await loadMemory(target);
        const memoryId = firstId(records.records[0]!);
        await quarantineMemory(target, memoryId, 'test-reviewer', 'T-08 evidence preservation drill');
        const entries = await listQuarantine(target);
        expect(entries).toHaveLength(1);
        expect(entries[0]).toMatchObject({ memoryId, actor: 'test-reviewer' });
        expect(entries[0]?.reason).toContain('T-08');
        expect((await loadMemory(target)).records).toHaveLength(1);
        const after = await auditMemory(target);
        expect(after.inventory.quarantined).toBe(1);
        return;
      }

      if (scenario.kind === 'runtime') {
        const directory = await mkdtemp(join(tmpdir(), 'agentshield-threat-runtime-'));
        const store = new (await import('@agentshield/runtime')).EventStore(join(directory, 'events.jsonl'));
        const lines = (await readFile(join(THREATS_ROOT, scenario.target), 'utf8')).split(/\r?\n/).filter(Boolean);
        for (const line of lines) await store.ingest(JSON.parse(line) as never);
        const events = await store.all();
        const requested = events.find((item) => item.type === 'tool.requested');
        expect(requested, 'fixture must contain a tool.requested event').toBeDefined();
        const policy: RuntimePolicy = { id: 'p-send', toolPattern: 'send_email', sensitivity: 'high', action: 'block' };
        expect(evaluateRuntimePolicy(requested!, [policy]).action).toBe('block');
        const graph = await store.graph('trace_t07');
        expect(graph.nodes.some((item) => item.kind === 'memory.retrieved')).toBe(true);
        expect(graph.nodes.some((item) => item.kind === 'tool.requested')).toBe(true);
        expect(buildEvidenceGraph(events, 'trace_t07').edges.length).toBeGreaterThan(0);
        return;
      }

      throw new Error(`Unhandled scenario kind: ${scenario.kind}`);
    });
  }
});
