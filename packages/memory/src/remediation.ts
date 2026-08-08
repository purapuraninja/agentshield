import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { createId } from '@agentshield/core';
import { loadMemory, quarantineMemory, restoreMemory } from './index.js';
import { dirname, join, resolve } from 'node:path';

export type RemediationState = 'planned' | 'approved' | 'executed' | 'rolled_back' | 'rejected';
export type RemediationAction = 'quarantine' | 'restore' | 'deprecate';

export interface RemediationStage {
  actor: string;
  reason: string;
  timestamp: string;
  expectedSourceHash: string;
}
export interface RemediationPlan {
  planId: string;
  memoryId: string;
  externalId: string;
  action: RemediationAction;
  state: RemediationState;
  expectedSourceHash: string;
  idempotencyKey: string;
  requireTwoPerson: boolean;
  planned: RemediationStage;
  approved?: RemediationStage;
  executed?: RemediationStage;
  rolledBack?: RemediationStage;
  rejected?: RemediationStage;
}
export interface RemediationFile { version: 1; plans: RemediationPlan[] }
export interface PlanOptions { idempotencyKey?: string; requireTwoPerson?: boolean }

function remediationDir(target: string): string {
  const absolute = resolve(target);
  return join(dirname(absolute), '.agentshield');
}

async function readRemediation(target: string): Promise<RemediationFile> {
  try { return JSON.parse(await readFile(join(remediationDir(target), 'remediation.json'), 'utf8')) as RemediationFile; }
  catch { return { version: 1, plans: [] }; }
}

async function writeRemediation(target: string, file: RemediationFile): Promise<void> {
  const path = join(remediationDir(target), 'remediation.json');
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(file, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  await rename(temporary, path);
}

export async function planRemediation(
  target: string, memoryId: string, action: RemediationAction, actor: string, reason: string,
  options: PlanOptions = {}
): Promise<RemediationPlan> {
  if (!actor.trim() || !reason.trim()) throw new Error('Remediation plan requires a non-empty actor and reason');
  const loaded = await loadMemory(target);
  const record = loaded.records.find((item) => item.memoryId === memoryId || item.externalId === memoryId);
  if (!record) throw new Error(`Memory record not found: ${memoryId}`);
  const idempotencyKey = options.idempotencyKey ?? createId('idem');
  const file = await readRemediation(target);
  const existing = file.plans.find((plan) => plan.idempotencyKey === idempotencyKey);
  if (existing) return existing;
  const plan: RemediationPlan = {
    planId: createId('rem'), memoryId: record.memoryId, externalId: record.externalId, action,
    state: 'planned', expectedSourceHash: record.contentHash, idempotencyKey,
    requireTwoPerson: options.requireTwoPerson ?? false,
    planned: { actor, reason, timestamp: new Date().toISOString(), expectedSourceHash: record.contentHash }
  };
  file.plans.push(plan);
  await writeRemediation(target, file);
  return plan;
}

export async function approveRemediation(target: string, planId: string, actor: string, reason: string): Promise<RemediationPlan> {
  if (!actor.trim() || !reason.trim()) throw new Error('Remediation approval requires a non-empty actor and reason');
  const file = await readRemediation(target);
  const plan = file.plans.find((item) => item.planId === planId);
  if (!plan) throw new Error(`Remediation plan not found: ${planId}`);
  if (plan.state !== 'planned') throw new Error(`Plan ${planId} is in state ${plan.state}, not planned`);
  if (plan.requireTwoPerson && plan.planned.actor === actor) throw new Error('Two-person approval requires a different approver than the planner');
  plan.state = 'approved';
  plan.approved = { actor, reason, timestamp: new Date().toISOString(), expectedSourceHash: plan.expectedSourceHash };
  await writeRemediation(target, file);
  return plan;
}

export async function executeRemediation(target: string, planId: string, actor: string): Promise<RemediationPlan> {
  if (!actor.trim()) throw new Error('Remediation execution requires a non-empty actor');
  const file = await readRemediation(target);
  const plan = file.plans.find((item) => item.planId === planId);
  if (!plan) throw new Error(`Remediation plan not found: ${planId}`);
  if (plan.state === 'executed') return plan;
  if (plan.state !== 'approved') throw new Error(`Plan ${planId} must be approved before execution (current: ${plan.state})`);
  const loaded = await loadMemory(target);
  const record = loaded.records.find((item) => item.memoryId === plan.memoryId || item.externalId === plan.externalId);
  if (!record) throw new Error(`Memory record not found for plan ${planId}: ${plan.memoryId}`);
  if (record.contentHash !== plan.expectedSourceHash) throw new Error(`Compare-and-swap failed: source hash changed since planning. Expected ${plan.expectedSourceHash}, actual ${record.contentHash}`);
  if (plan.action === 'quarantine') await quarantineMemory(target, plan.memoryId, actor, `remediation plan ${planId}`);
  else if (plan.action === 'restore') await restoreMemory(target, plan.memoryId, actor, `remediation plan ${planId}`);
  plan.state = 'executed';
  plan.executed = { actor, reason: plan.approved?.reason ?? plan.planned.reason, timestamp: new Date().toISOString(), expectedSourceHash: record.contentHash };
  await writeRemediation(target, file);
  return plan;
}

export async function rollbackRemediation(target: string, planId: string, actor: string, reason: string): Promise<RemediationPlan> {
  if (!actor.trim() || !reason.trim()) throw new Error('Remediation rollback requires a non-empty actor and reason');
  const file = await readRemediation(target);
  const plan = file.plans.find((item) => item.planId === planId);
  if (!plan) throw new Error(`Remediation plan not found: ${planId}`);
  if (plan.state !== 'executed') throw new Error(`Plan ${planId} is in state ${plan.state}, only executed plans can be rolled back`);
  if (plan.action === 'quarantine') await restoreMemory(target, plan.memoryId, actor, `rollback of plan ${planId}: ${reason}`);
  else if (plan.action === 'restore') await quarantineMemory(target, plan.memoryId, actor, `rollback of plan ${planId}: ${reason}`);
  plan.state = 'rolled_back';
  plan.rolledBack = { actor, reason, timestamp: new Date().toISOString(), expectedSourceHash: plan.expectedSourceHash };
  await writeRemediation(target, file);
  return plan;
}

export async function rejectRemediation(target: string, planId: string, actor: string, reason: string): Promise<RemediationPlan> {
  if (!actor.trim() || !reason.trim()) throw new Error('Remediation rejection requires a non-empty actor and reason');
  const file = await readRemediation(target);
  const plan = file.plans.find((item) => item.planId === planId);
  if (!plan) throw new Error(`Remediation plan not found: ${planId}`);
  if (plan.state !== 'planned' && plan.state !== 'approved') throw new Error(`Plan ${planId} is in state ${plan.state}, only planned or approved plans can be rejected`);
  plan.state = 'rejected';
  plan.rejected = { actor, reason, timestamp: new Date().toISOString(), expectedSourceHash: plan.expectedSourceHash };
  await writeRemediation(target, file);
  return plan;
}

export async function listRemediationPlans(target: string): Promise<RemediationPlan[]> {
  return (await readRemediation(target)).plans;
}

export async function getRemediationPlan(target: string, planId: string): Promise<RemediationPlan | undefined> {
  return (await readRemediation(target)).plans.find((plan) => plan.planId === planId);
}
