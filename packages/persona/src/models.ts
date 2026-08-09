import { z } from 'zod';
import { sha256 } from '@agentshield/core';

/**
 * AI model provider adapters.
 *
 * A persona is rendered into a plain system prompt. These adapters place that prompt into the
 * provider-native request shape (OpenAI messages, Anthropic system, Gemini systemInstruction,
 * Mistral messages, Ollama messages + options, OpenAI Responses instructions, generic system) so
 * a harness can attach the persona to a model call without translating formats by hand. The output
 * is deliberately pure and JSON-serializable: no network call is made and no credential is read —
 * this stays local-first like the rest of AgentShield.
 *
 * Security posture: the prompt is the operator's own persona, so it is returned verbatim (that is
 * the point of applying it). Advisory warnings from rendering are surfaced by `applyPersona` /
 * `renderPersona`; nothing here re-reads or transmits the prompt.
 */

export const MODEL_PROVIDERS = ['openai', 'anthropic', 'gemini', 'mistral', 'ollama', 'responses', 'generic'] as const;
export type ModelProvider = (typeof MODEL_PROVIDERS)[number];

export const modelRequestOptionsSchema = z.object({
  provider: z.enum(MODEL_PROVIDERS, { error: `Unsupported model provider. Supported: ${MODEL_PROVIDERS.join(', ')}` }),
  model: z.string().min(1, 'Model identifier is required'),
  temperature: z.number().min(0).max(2).optional(),
  maxTokens: z.number().int().positive().optional(),
  topP: z.number().min(0).max(1).optional()
});
export type ModelRequestOptions = z.infer<typeof modelRequestOptionsSchema>;

export interface ModelRequestResult {
  provider: ModelProvider;
  model: string;
  /** The exact persona prompt that was placed into the request. */
  systemPrompt: string;
  promptHash: string;
  /** Provider-native, JSON-serializable request (the system portion; the harness appends the user turn). */
  request: Record<string, unknown>;
  /** Human-readable pointer to where the prompt was injected, for logs and docs. */
  injectedAs: string;
}

/**
 * Builds the provider-native request carrying the given rendered persona prompt.
 *
 * The result is a "system portion": provider calls still need conversation messages, which belong to
 * the harness. For OpenAI the request is `messages`-based (harness appends the user turn), for
 * Anthropic the prompt goes into `system` and `max_tokens` defaults to 1024 because the API requires
 * it, and for Gemini it goes into `systemInstruction.parts` (harness appends `contents`). Mistral
 * and Ollama both accept OpenAI-style `messages` (Ollama additionally wraps sampling in `options`),
 * and `responses` uses the OpenAI Responses API shape (`instructions` + `input`).
 */
export function buildModelRequest(prompt: string, options: ModelRequestOptions): ModelRequestResult {
  if (!prompt.trim()) throw new Error('Cannot build a model request from an empty prompt');
  const parsed = modelRequestOptionsSchema.parse(options);
  const { provider, model, temperature, maxTokens, topP } = parsed;
  const request = buildProviderRequest(provider, { prompt, model, temperature, maxTokens, topP });
  return {
    provider,
    model,
    systemPrompt: prompt,
    promptHash: sha256(prompt),
    request,
    injectedAs: injectedAsFor(provider)
  };
}

function buildProviderRequest(provider: ModelProvider, parts: {
  prompt: string; model: string; temperature?: number; maxTokens?: number; topP?: number
}): Record<string, unknown> {
  const { prompt, model, temperature, maxTokens, topP } = parts;
  switch (provider) {
    case 'openai':
      return {
        model,
        messages: [{ role: 'system', content: prompt }],
        ...(temperature !== undefined ? { temperature } : {}),
        ...(maxTokens !== undefined ? { max_tokens: maxTokens } : {}),
        ...(topP !== undefined ? { top_p: topP } : {})
      };
    case 'anthropic':
      return {
        model,
        system: prompt,
        max_tokens: maxTokens ?? 1024,
        ...(temperature !== undefined ? { temperature } : {}),
        ...(topP !== undefined ? { top_p: topP } : {})
      };
    case 'gemini':
      return {
        model,
        systemInstruction: { parts: [{ text: prompt }] },
        ...(temperature !== undefined || maxTokens !== undefined || topP !== undefined
          ? { generationConfig: {
            ...(temperature !== undefined ? { temperature } : {}),
            ...(maxTokens !== undefined ? { maxOutputTokens: maxTokens } : {}),
            ...(topP !== undefined ? { topP } : {})
          } }
          : {})
      };
    case 'mistral':
      return {
        model,
        messages: [{ role: 'system', content: prompt }],
        ...(temperature !== undefined ? { temperature } : {}),
        ...(maxTokens !== undefined ? { max_tokens: maxTokens } : {}),
        ...(topP !== undefined ? { top_p: topP } : {})
      };
    case 'ollama':
      return {
        model,
        messages: [{ role: 'system', content: prompt }],
        stream: false,
        ...(temperature !== undefined || maxTokens !== undefined || topP !== undefined
          ? { options: {
            ...(temperature !== undefined ? { temperature } : {}),
            ...(maxTokens !== undefined ? { num_predict: maxTokens } : {}),
            ...(topP !== undefined ? { top_p: topP } : {})
          } }
          : {})
      };
    case 'responses':
      return {
        model,
        instructions: prompt,
        input: [],
        ...(temperature !== undefined ? { temperature } : {}),
        ...(maxTokens !== undefined ? { max_output_tokens: maxTokens } : {}),
        ...(topP !== undefined ? { top_p: topP } : {})
      };
    case 'generic':
      return {
        model,
        system: prompt,
        ...(temperature !== undefined ? { temperature } : {}),
        ...(maxTokens !== undefined ? { max_tokens: maxTokens } : {})
      };
  }
}

function injectedAsFor(provider: ModelProvider): string {
  return {
    openai: 'openai messages[0] with role=system (append the user turn)',
    anthropic: 'anthropic top-level system field (append conversation messages)',
    gemini: 'gemini systemInstruction.parts[0].text (append contents)',
    mistral: 'mistral messages[0] with role=system (append the user turn)',
    ollama: 'ollama messages[0] with role=system, stream=false (append the user turn)',
    responses: 'openai-responses top-level instructions field (append conversation items to input)',
    generic: 'generic top-level system field'
  }[provider];
}
