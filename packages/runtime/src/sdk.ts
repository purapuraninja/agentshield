import { createHmac, randomBytes } from 'node:crypto';
import { createId, sha256, type PolicyAction } from '@agentshield/core';
import { createRuntimeEvent, evaluateRuntimePolicy, buildEvidenceGraph, type RuntimePolicy, type CreateEventInput, type EvidenceGraph } from './index.js';
import type { RuntimeEvent } from '@agentshield/core';

export interface GateConfig {
  policies: RuntimePolicy[];
  signingKey?: string;
  failMode?: 'fail-open' | 'fail-closed';
  onEvent?: (event: RuntimeEvent) => void;
}

export interface GateContext {
  traceId: string;
  parentId?: string;
  causalityIds?: string[];
  actor: string;
}

export interface ToolRequest {
  tool: string;
  args?: unknown;
  sensitivity?: 'low' | 'medium' | 'high';
}

export interface MemoryWriteRequest {
  source: string;
  content?: unknown;
  sensitivity?: 'low' | 'medium' | 'high';
}

export interface GateResult {
  action: PolicyAction;
  policyIds: string[];
  reason: string;
  event: RuntimeEvent;
  receipt: string;
  approved: boolean;
}

/**
 * Synchronous policy gate for AI agent runtime. Intercepts tool calls and memory writes before they
 * execute, evaluates runtime policy, emits sanitized events, and returns signed action receipts.
 * Default fail mode is fail-open (allow on policy miss); set failMode: 'fail-closed' to block when no
 * policy explicitly allows a sensitive action.
 */
export class AgentShieldGate {
  readonly config: GateConfig;
  private readonly signingKey: string;

  constructor(config: GateConfig) {
    this.config = config;
    this.signingKey = config.signingKey ?? randomBytes(32).toString('hex');
  }

  beforeTool(request: ToolRequest, context: GateContext): GateResult {
    const input: CreateEventInput = {
      traceId: context.traceId, parentId: context.parentId, causalityIds: context.causalityIds,
      type: 'tool.requested', actor: context.actor, target: request.tool,
      metadata: { sensitivity: request.sensitivity ?? 'low' }
    };
    const event = createRuntimeEvent(input);
    const decision = evaluateRuntimePolicy(event, this.config.policies);
    const action = this.resolveAction(decision.action, request.sensitivity);
    this.emit(event);
    return { action, policyIds: decision.policyIds, reason: decision.reason, event, receipt: this.signReceipt(event, action), approved: action === 'allow' || action === 'warn' };
  }

  beforeMemoryWrite(request: MemoryWriteRequest, context: GateContext): GateResult {
    const input: CreateEventInput = {
      traceId: context.traceId, parentId: context.parentId, causalityIds: context.causalityIds,
      type: 'memory.proposed', actor: context.actor, target: request.source,
      metadata: { source: request.source, sensitivity: request.sensitivity ?? 'low' }
    };
    const event = createRuntimeEvent(input);
    const decision = evaluateRuntimePolicy(event, this.config.policies);
    const action = this.resolveAction(decision.action, request.sensitivity);
    this.emit(event);
    return { action, policyIds: decision.policyIds, reason: decision.reason, event, receipt: this.signReceipt(event, action), approved: action === 'allow' || action === 'warn' };
  }

  requestApproval(tool: string, context: GateContext): RuntimeEvent {
    const event = createRuntimeEvent({ traceId: context.traceId, parentId: context.parentId, type: 'approval.requested', actor: context.actor, target: tool });
    this.emit(event);
    return event;
  }

  resolveApproval(eventId: string, approved: boolean, actor: string, traceId: string): RuntimeEvent {
    const event = createRuntimeEvent({ traceId, causalityIds: [eventId], type: 'approval.resolved', actor, metadata: { approved } });
    this.emit(event);
    return event;
  }

  incidentEvidence(events: RuntimeEvent[], traceId: string): EvidenceGraph & { receipt: string } {
    const graph = buildEvidenceGraph(events, traceId);
    return { ...graph, receipt: this.signReceipt({ eventId: traceId, timestamp: new Date().toISOString() } as RuntimeEvent, 'allow') };
  }

  private resolveAction(action: PolicyAction, sensitivity?: 'low' | 'medium' | 'high'): PolicyAction {
    if (action !== 'allow' || this.config.failMode !== 'fail-closed') return action;
    return sensitivity === 'high' ? 'require_review' : 'allow';
  }

  private emit(event: RuntimeEvent): void {
    this.config.onEvent?.(event);
  }

  private signReceipt(event: RuntimeEvent, action: PolicyAction): string {
    const payload = `${event.eventId}|${event.traceId}|${action}|${event.timestamp}`;
    const hmac = createHmac('sha256', this.signingKey).update(payload).digest('hex');
    return `as1:${hmac}`;
  }
}

export { createId, sha256 };
