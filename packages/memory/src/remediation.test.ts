import { copyFile, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { basename, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { describe, expect, it } from 'vitest';
import {
  auditMemory, approveRemediation, executeRemediation, getRemediationPlan, listRemediationPlans,
  loadMemory, planRemediation, rejectRemediation, rollbackRemediation
} from './index.js';

async function tempMemory(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'agentshield-rem-'));
  const source = resolve('fixtures/poisoned-memory/memories.jsonl');
  const target = join(directory, basename(source));
  await copyFile(source, target);
  return target;
}

describe('remediation state machine', () => {
  it('flows planned -> approved -> executed -> rolled_back with idempotent planning', async () => {
    const target = await tempMemory();
    const records = await loadMemory(target);
    const poison = records.records.find((item) => item.externalId === 'web-override')!;

    const plan = await planRemediation(target, poison.memoryId, 'quarantine', 'analyst', 'poisoned web content', { idempotencyKey: 'key-1' });
    expect(plan.state).toBe('planned');
    expect(plan.expectedSourceHash).toBe(poison.contentHash);

    const rePlanned = await planRemediation(target, poison.memoryId, 'quarantine', 'analyst', 'duplicate', { idempotencyKey: 'key-1' });
    expect(rePlanned.planId).toBe(plan.planId);

    const approved = await approveRemediation(target, plan.planId, 'reviewer', 'evidence reviewed');
    expect(approved.state).toBe('approved');
    expect(approved.approved?.actor).toBe('reviewer');

    const executed = await executeRemediation(target, plan.planId, 'system');
    expect(executed.state).toBe('executed');
    expect((await auditMemory(target)).inventory.quarantined).toBe(1);

    const rolled = await rollbackRemediation(target, plan.planId, 'reviewer', 'false positive after deeper review');
    expect(rolled.state).toBe('rolled_back');
    expect((await auditMemory(target)).inventory.quarantined).toBe(0);
  });

  it('requires a different approver for two-person plans', async () => {
    const target = await tempMemory();
    const records = await loadMemory(target);
    const record = records.records[0]!;
    const plan = await planRemediation(target, record.memoryId, 'quarantine', 'analyst', 'high-impact', { requireTwoPerson: true });
    await expect(approveRemediation(target, plan.planId, 'analyst', 'same person')).rejects.toThrow(/Two-person/);
    const approved = await approveRemediation(target, plan.planId, 'manager', 'approved by manager');
    expect(approved.state).toBe('approved');
  });

  it('fails compare-and-swap when the source hash changed since planning', async () => {
    const target = await tempMemory();
    const records = await loadMemory(target);
    const record = records.records[0]!;
    const plan = await planRemediation(target, record.memoryId, 'quarantine', 'analyst', 'test');
    await approveRemediation(target, plan.planId, 'reviewer', 'approved');
    const content = await readFile(target, 'utf8');
    await writeFile(target, content.replace('singapore', 'jakarta-replaced'), 'utf8');
    await expect(executeRemediation(target, plan.planId, 'system')).rejects.toThrow(/Compare-and-swap failed/);
  });

  it('rejects a planned plan and prevents execution', async () => {
    const target = await tempMemory();
    const records = await loadMemory(target);
    const record = records.records[0]!;
    const plan = await planRemediation(target, record.memoryId, 'quarantine', 'analyst', 'test');
    const rejected = await rejectRemediation(target, plan.planId, 'reviewer', 'not warranted');
    expect(rejected.state).toBe('rejected');
    await expect(executeRemediation(target, plan.planId, 'system')).rejects.toThrow(/must be approved/);
  });

  it('lists and retrieves plans', async () => {
    const target = await tempMemory();
    const records = await loadMemory(target);
    const record = records.records[0]!;
    const plan = await planRemediation(target, record.memoryId, 'deprecate', 'analyst', 'stale');
    expect((await listRemediationPlans(target))).toHaveLength(1);
    expect((await getRemediationPlan(target, plan.planId))?.planId).toBe(plan.planId);
    expect(await getRemediationPlan(target, 'nonexistent')).toBeUndefined();
  });
});
