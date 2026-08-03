import { copyFile, mkdtemp } from 'node:fs/promises';
import { basename, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, it } from 'vitest';
import { auditMemory, listQuarantine, loadMemory, quarantineMemory, restoreMemory } from './index.js';

async function temporaryMemory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'agentshield-memory-'));
  const source = resolve('fixtures/poisoned-memory/memories.jsonl');
  const target = join(directory, basename(source));
  await copyFile(source, target);
  return target;
}

describe('memory intelligence', () => {
  it('detects duplicate, conflict, staleness, and poisoning deterministically', async () => {
    const report = await auditMemory(resolve('fixtures/poisoned-memory/memories.jsonl'));
    const ids = report.findings.map((item) => item.ruleId);
    expect(ids).toEqual(expect.arrayContaining(['AS-ME-001', 'AS-ME-003', 'AS-ME-005', 'AS-ME-010']));
    expect(report.findings.find((item) => item.ruleId === 'AS-ME-010')?.severity).toBe('critical');
    expect(report.assessments).toHaveLength(5);
  });

  it('quarantines without modifying source and restores reversibly', async () => {
    const target = await temporaryMemory();
    const original = await loadMemory(target);
    const poison = original.records.find((item) => item.externalId === 'web-override')!;
    await quarantineMemory(target, poison.memoryId, 'test-reviewer', 'deterministic poisoning fixture');
    const after = await auditMemory(target);
    expect(after.inventory.quarantined).toBe(1);
    expect(after.inventory.audited).toBe(4);
    expect((await loadMemory(target)).records).toHaveLength(5);
    expect((await listQuarantine(target))[0]).not.toHaveProperty('snapshot');
    await restoreMemory(target, poison.memoryId, 'test-reviewer', 'rollback drill');
    expect((await auditMemory(target)).inventory.quarantined).toBe(0);
  });
});
