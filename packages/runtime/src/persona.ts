import { applyPersona, buildModelRequest, modelRequestOptionsSchema, type AppliedPersona, type ModelRequestOptions, type ModelRequestResult } from '@agentshield/persona';
import { AgentShieldGate, type GateContext } from './sdk.js';
import type { RuntimeEvent } from '@agentshield/core';

/**
 * Runtime ↔ persona bridge.
 *
 * One call for an agent harness: apply a persona from the local store (rendering + immutable
 * application receipt), translate the rendered prompt into a provider-native model request, and —
 * when a gate is supplied — record the application as a sanitized `persona.applied` runtime event so
 * it shows up in the evidence graph alongside tool and memory actions.
 *
 * Security posture: the raw prompt is returned to the harness (it must be sent to the model), but it
 * is never written into the runtime event stream — only the prompt digest and the persona receipt are
 * recorded, consistent with `AgentShieldGate.recordPersona`.
 */

export interface PersonaModelOptions extends ModelRequestOptions {
  actor: string;
  reason?: string;
  variables?: Record<string, string>;
}

export interface PersonaGateRecording {
  gate: AgentShieldGate;
  context: GateContext;
}

export interface PersonaModelApplication {
  applied: AppliedPersona;
  request: ModelRequestResult;
  /** Present when `recording` was provided. */
  event?: RuntimeEvent;
  /** Signed `as1:` gate receipt (distinct from the `persona1:` application receipt), present when `recording` was provided. */
  gateReceipt?: string;
}

export async function applyPersonaToModel(
  target: string,
  personaId: string,
  options: PersonaModelOptions,
  recording?: PersonaGateRecording
): Promise<PersonaModelApplication> {
  // Validate provider/model/sampling up front so a bad invocation fails BEFORE an application
  // receipt is chained into the audit log (same contract as the CLI and REST API).
  modelRequestOptionsSchema.parse(options);
  const applied = await applyPersona(target, personaId, {
    actor: options.actor, reason: options.reason, variables: options.variables
  });
  const request = buildModelRequest(applied.prompt, options);
  if (!recording) return { applied, request };
  const gateResult = recording.gate.recordPersona({
    personaId: applied.personaId,
    version: applied.version,
    promptHash: applied.promptHash,
    receipt: applied.receipt,
    reason: options.reason
  }, recording.context);
  return { applied, request, event: gateResult.event, gateReceipt: gateResult.receipt };
}
