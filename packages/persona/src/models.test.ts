import { describe, expect, it } from 'vitest';
import { buildModelRequest, MODEL_PROVIDERS, modelRequestOptionsSchema, type ModelRequestOptions } from './models.js';

const PROMPT = 'You are the AgentShield code reviewer. Focus on secrets first.';

describe('model provider adapters', () => {
  it('builds an OpenAI request with the persona as the system message', () => {
    const result = buildModelRequest(PROMPT, { provider: 'openai', model: 'gpt-4o', temperature: 0.2, maxTokens: 800 });
    expect(result.provider).toBe('openai');
    expect(result.injectedAs).toContain('messages[0]');
    expect(result.request).toEqual({
      model: 'gpt-4o',
      messages: [{ role: 'system', content: PROMPT }],
      temperature: 0.2,
      max_tokens: 800
    });
  });

  it('builds an Anthropic request with the persona in the system field and a required max_tokens default', () => {
    const result = buildModelRequest(PROMPT, { provider: 'anthropic', model: 'claude-3-5-sonnet' });
    expect(result.request).toEqual({ model: 'claude-3-5-sonnet', system: PROMPT, max_tokens: 1024 });
    expect(result.injectedAs).toContain('system field');
  });

  it('builds a Gemini request with the persona in systemInstruction parts', () => {
    const result = buildModelRequest(PROMPT, { provider: 'gemini', model: 'gemini-1.5-pro', maxTokens: 512, topP: 0.9 });
    expect(result.request).toEqual({
      model: 'gemini-1.5-pro',
      systemInstruction: { parts: [{ text: PROMPT }] },
      generationConfig: { maxOutputTokens: 512, topP: 0.9 }
    });
    expect(result.injectedAs).toContain('systemInstruction.parts[0].text');
  });

  it('builds a generic request with a top-level system field', () => {
    const result = buildModelRequest(PROMPT, { provider: 'generic', model: 'any-model', temperature: 1 });
    expect(result.request).toEqual({ model: 'any-model', system: PROMPT, temperature: 1 });
  });

  it('builds a Mistral request with the persona as the system message (OpenAI-compatible)', () => {
    const result = buildModelRequest(PROMPT, { provider: 'mistral', model: 'mistral-large-latest', temperature: 0.3, maxTokens: 400 });
    expect(result.request).toEqual({
      model: 'mistral-large-latest', messages: [{ role: 'system', content: PROMPT }], temperature: 0.3, max_tokens: 400
    });
  });

  it('builds an Ollama request with sampling wrapped in options', () => {
    const result = buildModelRequest(PROMPT, { provider: 'ollama', model: 'llama3.1', maxTokens: 256, topP: 0.9 });
    expect(result.request).toEqual({
      model: 'llama3.1', messages: [{ role: 'system', content: PROMPT }], stream: false,
      options: { num_predict: 256, top_p: 0.9 }
    });
    const bare = buildModelRequest(PROMPT, { provider: 'ollama', model: 'llama3.1' });
    expect(bare.request).toEqual({ model: 'llama3.1', messages: [{ role: 'system', content: PROMPT }], stream: false });
  });

  it('builds an OpenAI Responses API request with instructions and an empty input', () => {
    const result = buildModelRequest(PROMPT, { provider: 'responses', model: 'gpt-4o', maxTokens: 1024 });
    expect(result.request).toEqual({
      model: 'gpt-4o', instructions: PROMPT, input: [], max_output_tokens: 1024
    });
    expect(result.injectedAs).toContain('instructions');
  });

  it('passes top_p through for OpenAI like the other providers', () => {
    const result = buildModelRequest(PROMPT, { provider: 'openai', model: 'gpt-4o', topP: 0.8, maxTokens: 256 });
    expect(result.request).toEqual({
      model: 'gpt-4o', messages: [{ role: 'system', content: PROMPT }], max_tokens: 256, top_p: 0.8
    });
  });

  it('omits optional sampling parameters when they are not provided', () => {
    const openai = buildModelRequest(PROMPT, { provider: 'openai', model: 'gpt-4o' });
    expect(openai.request).toEqual({ model: 'gpt-4o', messages: [{ role: 'system', content: PROMPT }] });
    const gemini = buildModelRequest(PROMPT, { provider: 'gemini', model: 'gemini-1.5-pro' });
    expect(gemini.request).toEqual({ model: 'gemini-1.5-pro', systemInstruction: { parts: [{ text: PROMPT }] } });
  });

  it('returns a stable prompt hash and a JSON-serializable request', () => {
    const options: ModelRequestOptions = { provider: 'openai', model: 'gpt-4o' };
    const result = buildModelRequest(PROMPT, options);
    expect(result.promptHash).toMatch(/^sha256:/);
    expect(JSON.parse(JSON.stringify(result.request))).toEqual(result.request);
  });
});

describe('model request validation', () => {
  it('rejects unknown providers and empty models', () => {
    expect(() => buildModelRequest(PROMPT, { provider: 'athena' as 'openai', model: 'x' })).toThrow(/Unsupported model provider/);
    expect(() => buildModelRequest(PROMPT, { provider: 'openai', model: '' })).toThrow(/required/);
    expect(() => buildModelRequest('', { provider: 'openai', model: 'gpt-4o' })).toThrow(/empty prompt/);
  });

  it('rejects out-of-range sampling parameters', () => {
    expect(() => buildModelRequest(PROMPT, { provider: 'openai', model: 'gpt-4o', temperature: 3 })).toThrow(/temperature/);
    expect(() => buildModelRequest(PROMPT, { provider: 'openai', model: 'gpt-4o', topP: 1.5 })).toThrow(/topP/);
    expect(() => buildModelRequest(PROMPT, { provider: 'openai', model: 'gpt-4o', maxTokens: 0 })).toThrow(/maxTokens/);
    expect(() => buildModelRequest(PROMPT, { provider: 'openai', model: 'gpt-4o', maxTokens: 1.5 })).toThrow(/maxTokens/);
  });

  it('validates the options schema standalone (CLI validates before recording an application receipt)', () => {
    expect(modelRequestOptionsSchema.parse({ provider: 'openai', model: 'gpt-4o' }).model).toBe('gpt-4o');
    expect(() => modelRequestOptionsSchema.parse({ provider: 'athena', model: 'x' })).toThrow(/Unsupported model provider/);
    expect(() => modelRequestOptionsSchema.parse({ provider: 'openai', model: '' })).toThrow(/required/);
    expect(() => modelRequestOptionsSchema.parse({ provider: 'openai', model: 'x', temperature: -1 })).toThrow(/temperature/);
  });

  it('exposes every supported provider for CLI help', () => {
    expect(MODEL_PROVIDERS).toEqual(['openai', 'anthropic', 'gemini', 'mistral', 'ollama', 'responses', 'generic']);
  });
});
