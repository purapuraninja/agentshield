import { describe, expect, it } from 'vitest';
import { buildModelRequest } from './models.js';
import { chatWithModel, PROVIDER_ENV_KEYS } from './chat.js';

interface CapturedCall { input: string; init: RequestInit }
type FetchWithCapture = typeof fetch & { captured: CapturedCall };

function mockFetch(response: { status?: number; body: Record<string, unknown> }): typeof fetch {
  const impl = (async (input: RequestInfo | URL, init?: RequestInit) => {
    impl.captured = { input: String(input), init: init as RequestInit };
    return {
      ok: (response.status ?? 200) < 300,
      status: response.status ?? 200,
      json: async () => response.body
    } as Response;
  }) as unknown as FetchWithCapture;
  return impl;
}

function captured(fetchImpl: typeof fetch): CapturedCall {
  return (fetchImpl as unknown as FetchWithCapture).captured;
}

const base = { provider: 'openai' as const, model: 'gpt-4o', systemPrompt: 'Kamu adalah asisten pribadi.', promptHash: 'x', injectedAs: 'x' };

describe('chatWithModel', () => {
  it('sends the persona system message plus the user turn to OpenAI with a bearer key', async () => {
    const fetchImpl = mockFetch({ body: { choices: [{ message: { content: 'Halo! Saya asisten pribadi Anda.' } }], usage: { prompt_tokens: 10, completion_tokens: 5 } } });
    const built = buildModelRequest(base.systemPrompt, { provider: 'openai', model: 'gpt-4o' });
    const result = await chatWithModel(built, 'Siapa kamu?', { apiKey: 'sk-test', fetchImpl });
    expect(result.message).toBe('Halo! Saya asisten pribadi Anda.');
    expect(result.usage).toEqual({ promptTokens: 10, completionTokens: 5 });
    const call = captured(fetchImpl);
    expect(call.input).toBe('https://api.openai.com/v1/chat/completions');
    expect(call.init.headers).toMatchObject({ authorization: 'Bearer sk-test' });
    const body = JSON.parse(String(call.init.body)) as { messages: Array<{ role: string; content: string }> };
    expect(body.messages).toEqual([
      { role: 'system', content: 'Kamu adalah asisten pribadi.' },
      { role: 'user', content: 'Siapa kamu?' }
    ]);
  });

  it('sends Anthropic headers and parses text blocks', async () => {
    const fetchImpl = mockFetch({ body: { content: [{ type: 'text', text: 'Saya asisten Anda.' }], usage: { input_tokens: 3, output_tokens: 7 } } });
    const built = buildModelRequest('Jawab singkat.', { provider: 'anthropic', model: 'claude-sonnet-4-20250514' });
    const result = await chatWithModel(built, 'Halo', { apiKey: 'sk-ant-test', fetchImpl });
    expect(result.message).toBe('Saya asisten Anda.');
    const call = captured(fetchImpl);
    expect(call.init.headers).toMatchObject({ 'x-api-key': 'sk-ant-test', 'anthropic-version': '2023-06-01' });
    const body = JSON.parse(String(call.init.body)) as { system: string; messages: Array<{ role: string }> };
    expect(body.system).toBe('Jawab singkat.');
    expect(body.messages).toEqual([{ role: 'user', content: 'Halo' }]);
  });

  it('calls Gemini with the model and key in the URL and parses candidates', async () => {
    const fetchImpl = mockFetch({ body: { candidates: [{ content: { parts: [{ text: 'Halo dari Gemini.' }] } }], usageMetadata: { promptTokenCount: 4, candidatesTokenCount: 6 } } });
    const built = buildModelRequest('Jawab pendek.', { provider: 'gemini', model: 'gemini-2.0-flash' });
    const result = await chatWithModel(built, 'Halo', { apiKey: 'gem-test', fetchImpl });
    expect(result.message).toBe('Halo dari Gemini.');
    const call = captured(fetchImpl);
    expect(call.input).toContain('/v1beta/models/gemini-2.0-flash:generateContent?key=gem-test');
    const body = JSON.parse(String(call.init.body)) as { contents: Array<{ role: string; parts: Array<{ text: string }> }> };
    expect(body.contents).toEqual([{ role: 'user', parts: [{ text: 'Halo' }] }]);
  });

  it('calls Ollama locally without auth and parses message content', async () => {
    const fetchImpl = mockFetch({ body: { message: { content: 'Halo dari llama3.1!' }, prompt_eval_count: 8, eval_count: 4 } });
    const built = buildModelRequest('Kamu ramah.', { provider: 'ollama', model: 'llama3.1' });
    const result = await chatWithModel(built, 'Halo', { fetchImpl });
    expect(result.message).toBe('Halo dari llama3.1!');
    const call = captured(fetchImpl);
    expect(call.input).toBe('http://127.0.0.1:11434/api/chat');
    expect(call.init.headers).not.toHaveProperty('authorization');
    expect(JSON.parse(String(call.init.body))).toMatchObject({ stream: false, model: 'llama3.1' });
  });

  it('appends conversation items to the Responses API input', async () => {
    const fetchImpl = mockFetch({ body: { output_text: 'Jawaban Responses.' } });
    const built = buildModelRequest('Instruksi.', { provider: 'responses', model: 'gpt-4o' });
    const result = await chatWithModel(built, 'Tes', { apiKey: 'sk-test', fetchImpl });
    expect(result.message).toBe('Jawaban Responses.');
    const body = JSON.parse(String(captured(fetchImpl).init.body)) as { input: Array<{ role: string; content: string }> };
    expect(body.input).toEqual([{ role: 'user', content: 'Tes' }]);
  });

  it('requires a key for keyed providers and surfaces provider error messages', async () => {
    const built = buildModelRequest('p', { provider: 'openai', model: 'gpt-4o' });
    await expect(chatWithModel(built, 'Halo', {})).rejects.toThrow(/OPENAI_API_KEY/);

    const fetchImpl = mockFetch({ status: 401, body: { error: { message: 'Incorrect API key provided' } } });
    await expect(chatWithModel(built, 'Halo', { apiKey: 'bad', fetchImpl })).rejects.toThrow(/Incorrect API key/);
  });

  it('requires a base URL for the generic provider', async () => {
    const built = buildModelRequest('p', { provider: 'generic', model: 'local-model' });
    await expect(chatWithModel(built, 'Halo', {})).rejects.toThrow(/base-url/);
  });

  it('rejects an empty model reply instead of returning a blank message', async () => {
    const fetchImpl = mockFetch({ body: { choices: [] } });
    const built = buildModelRequest('p', { provider: 'openai', model: 'gpt-4o' });
    await expect(chatWithModel(built, 'Halo', { apiKey: 'sk-test', fetchImpl })).rejects.toThrow(/empty reply/);
  });

  it('declares env vars for every keyed provider', () => {
    expect(PROVIDER_ENV_KEYS.openai).toBe('OPENAI_API_KEY');
    expect(PROVIDER_ENV_KEYS.anthropic).toBe('ANTHROPIC_API_KEY');
    expect(PROVIDER_ENV_KEYS.gemini).toBe('GEMINI_API_KEY');
    expect(PROVIDER_ENV_KEYS.mistral).toBe('MISTRAL_API_KEY');
    expect(PROVIDER_ENV_KEYS.ollama).toBe('');
  });
});
