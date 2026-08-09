import type { ModelProvider, ModelRequestResult } from './models.js';

/**
 * Model chat adapter.
 *
 * `buildModelRequest` produces the provider-native "system portion" of a request; this module appends
 * the operator's test message and performs the actual network call to the provider, using an API key
 * the operator supplies. The key is read from the environment or passed explicitly and is never
 * persisted by AgentShield.
 *
 * Security posture: this is an explicit, opt-in, operator-initiated capability. It sends the
 * operator's own persona prompt plus their message to the provider of their choice with their own
 * credential. Nothing here stores the key, the prompt, or the reply — the response is streamed back
 * to the caller only.
 */

export interface ChatCallOptions {
  /** Provider API key. Prefer the provider env var; never stored by AgentShield. */
  apiKey?: string;
  /** Endpoint override (required for `generic`). */
  baseUrl?: string;
  /** Request timeout in milliseconds. Defaults to 60s. */
  timeoutMs?: number;
  /** Injectable fetch for tests. */
  fetchImpl?: typeof fetch;
}

export interface ChatResult {
  provider: ModelProvider;
  model: string;
  /** The assistant's reply text extracted from the provider response. */
  message: string;
  /** Token usage when the provider reports it. */
  usage?: { promptTokens?: number; completionTokens?: number };
  /** Raw provider response for --json output. */
  raw: unknown;
}

/** Environment variable that holds the API key for each provider (empty = no key needed). */
export const PROVIDER_ENV_KEYS: Record<ModelProvider, string> = {
  openai: 'OPENAI_API_KEY',
  anthropic: 'ANTHROPIC_API_KEY',
  gemini: 'GEMINI_API_KEY',
  mistral: 'MISTRAL_API_KEY',
  ollama: '',
  responses: 'OPENAI_API_KEY',
  generic: ''
};

const ENDPOINTS: Record<ModelProvider, string> = {
  openai: 'https://api.openai.com/v1/chat/completions',
  anthropic: 'https://api.anthropic.com/v1/messages',
  gemini: 'https://generativelanguage.googleapis.com/v1beta/models',
  mistral: 'https://api.mistral.ai/v1/chat/completions',
  ollama: 'http://127.0.0.1:11434/api/chat',
  responses: 'https://api.openai.com/v1/responses',
  generic: ''
};

interface ProviderCall {
  url: string;
  headers: Record<string, string>;
  payload: Record<string, unknown>;
}

function keyHint(provider: ModelProvider): string {
  const variable = PROVIDER_ENV_KEYS[provider];
  return variable ? `Set ${variable} or pass --api-key.` : 'This provider does not need an API key.';
}

function providerCall(built: ModelRequestResult, userMessage: string, options: ChatCallOptions): ProviderCall {
  const apiKey = options.apiKey ?? '';
  const json = { 'content-type': 'application/json' };
  const { provider } = built;
  const request = built.request as Record<string, unknown>;

  switch (provider) {
    case 'openai':
    case 'mistral': {
      const messages = [...(request.messages as Array<Record<string, unknown>>), { role: 'user', content: userMessage }];
      return { url: ENDPOINTS[provider], headers: { ...json, authorization: `Bearer ${apiKey}` }, payload: { ...request, messages } };
    }
    case 'ollama': {
      const messages = [...(request.messages as Array<Record<string, unknown>>), { role: 'user', content: userMessage }];
      return { url: ENDPOINTS.ollama, headers: json, payload: { ...request, messages } };
    }
    case 'anthropic':
      return {
        url: ENDPOINTS.anthropic,
        headers: { ...json, 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
        payload: { ...request, messages: [{ role: 'user', content: userMessage }] }
      };
    case 'responses':
      return {
        url: ENDPOINTS.responses,
        headers: { ...json, authorization: `Bearer ${apiKey}` },
        payload: { ...request, input: [{ role: 'user', content: userMessage }] }
      };
    case 'gemini': {
      const model = String(request.model);
      const url = `${ENDPOINTS.gemini}/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(apiKey)}`;
      return {
        url,
        headers: json,
        payload: { ...request, contents: [{ role: 'user', parts: [{ text: userMessage }] }] }
      };
    }
    case 'generic': {
      // The generic adapter declares an OpenAI-style system field; assume an OpenAI-compatible
      // /chat/completions endpoint and rebuild the conversation from the rendered prompt.
      if (!options.baseUrl) throw new Error('generic provider chat requires --base-url <endpoint> (or AGENTSHIELD_MODEL_BASE_URL)');
      const payload = {
        model: request.model,
        messages: [
          { role: 'system', content: built.systemPrompt },
          { role: 'user', content: userMessage }
        ],
        ...(request.temperature !== undefined ? { temperature: request.temperature } : {}),
        ...(request.max_tokens !== undefined ? { max_tokens: request.max_tokens } : {})
      };
      const headers: Record<string, string> = { ...json };
      if (apiKey) headers.authorization = `Bearer ${apiKey}`;
      return { url: options.baseUrl, headers, payload };
    }
  }
}

function extractReply(provider: ModelProvider, data: Record<string, unknown>): string {
  const content = (item: unknown): string => {
    const text = (item as { text?: string } | undefined)?.text;
    return typeof text === 'string' ? text : '';
  };
  switch (provider) {
    case 'anthropic': {
      const blocks = Array.isArray(data.content) ? data.content as Array<unknown> : [];
      return blocks.map(content).join('').trim();
    }
    case 'gemini': {
      const candidates = Array.isArray(data.candidates) ? data.candidates as Array<{ content?: { parts?: Array<unknown> } }> : [];
      return candidates.flatMap((candidate) => candidate.content?.parts ?? []).map(content).join('').trim();
    }
    case 'responses': {
      if (typeof data.output_text === 'string') return data.output_text.trim();
      const output = Array.isArray(data.output) ? data.output as Array<{ type?: string; content?: Array<unknown> }> : [];
      return output.filter((item) => item.type === 'message').flatMap((item) => item.content ?? []).map(content).join('').trim();
    }
    case 'ollama': {
      const message = data.message as { content?: string } | undefined;
      return (message?.content ?? '').trim();
    }
    default: {
      const choices = Array.isArray(data.choices) ? data.choices as Array<{ message?: { content?: string } }> : [];
      return choices.map((choice) => choice.message?.content ?? '').join('').trim();
    }
  }
}

function extractUsage(provider: ModelProvider, data: Record<string, unknown>): ChatResult['usage'] {
  const usage = data.usage as { prompt_tokens?: number; completion_tokens?: number; input_tokens?: number; output_tokens?: number } | undefined;
  const promptEval = data.prompt_eval_count;
  const completionEval = data.eval_count;
  const metadata = data.usageMetadata as { promptTokenCount?: number; candidatesTokenCount?: number } | undefined;
  switch (provider) {
    case 'anthropic':
    case 'responses':
      return { promptTokens: usage?.input_tokens, completionTokens: usage?.output_tokens };
    case 'ollama':
      return { promptTokens: typeof promptEval === 'number' ? promptEval : undefined, completionTokens: typeof completionEval === 'number' ? completionEval : undefined };
    case 'gemini':
      return { promptTokens: metadata?.promptTokenCount, completionTokens: metadata?.candidatesTokenCount };
    default:
      return { promptTokens: usage?.prompt_tokens, completionTokens: usage?.completion_tokens };
  }
}

function requiresKey(provider: ModelProvider): boolean {
  return provider === 'openai' || provider === 'anthropic' || provider === 'gemini' || provider === 'mistral' || provider === 'responses';
}

/**
 * Sends the built persona request plus the operator's message to the provider and returns the
 * assistant's reply. The API key comes from `options.apiKey` (typically an env var) and is never
 * persisted. Throws on missing key, network failure, timeout, or non-2xx provider response.
 */
export async function chatWithModel(built: ModelRequestResult, userMessage: string, options: ChatCallOptions = {}): Promise<ChatResult> {
  if (!userMessage.trim()) throw new Error('Chat message must not be empty');
  if (requiresKey(built.provider) && !options.apiKey) {
    throw new Error(`No API key for ${built.provider}. ${keyHint(built.provider)}`);
  }
  const fetchImpl = options.fetchImpl ?? fetch;
  const call = providerCall(built, userMessage, options);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? 60_000);
  let response: Response;
  try {
    response = await fetchImpl(call.url, {
      method: 'POST', headers: call.headers, body: JSON.stringify(call.payload), signal: controller.signal
    });
  } catch (error) {
    if (controller.signal.aborted) throw new Error(`${built.provider}: request timed out after ${Math.round((options.timeoutMs ?? 60_000) / 1000)}s`);
    throw new Error(`${built.provider}: network error — ${error instanceof Error ? error.message : String(error)}`);
  }

  // The timeout stays armed until the body is read, so a slow-dripping response cannot hang the call.
  let data: Record<string, unknown>;
  try { data = await response.json() as Record<string, unknown>; }
  catch { throw new Error(`${built.provider}: non-JSON response (HTTP ${response.status})`); }
  finally { clearTimeout(timeout); }

  if (!response.ok) {
    const message = (data.error as { message?: string } | undefined)?.message ?? (data.message as string | undefined) ?? `HTTP ${response.status}`;
    throw new Error(`${built.provider} ${built.model} error: ${message}`);
  }

  const reply = extractReply(built.provider, data);
  if (!reply) throw new Error(`${built.provider}: empty reply from the model (HTTP ${response.status})`);
  return { provider: built.provider, model: built.model, message: reply, usage: extractUsage(built.provider, data), raw: data };
}
