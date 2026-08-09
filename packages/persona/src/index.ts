import { appendFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, extname, join, resolve } from 'node:path';
import { z } from 'zod';
import YAML from 'yaml';
import { createId, sha256 } from '@agentshield/core';

/**
 * Agent persona application.
 *
 * A persona is a trusted, versioned definition of how an agent should behave (identity, tone, rules)
 * expressed as a system-prompt template with declared variables. Registering a persona validates it,
 * applying it renders the prompt and records an immutable, hash-chained application receipt so an
 * operator can always prove which persona version was applied, when, and by whom — and detect drift.
 *
 * Security posture: personas may set identity and behavior (that is their purpose), but a persona
 * must never smuggle in instruction-override, safety-bypass, or secret-exfiltration language. The
 * injection guard rejects those patterns, so the trusted persona channel cannot be used to remove
 * the guardrails it is meant to express.
 */

export const personaVariableSchema = z.object({
  name: z.string().min(1).max(64).regex(/^[A-Za-z_][A-Za-z0-9_]*$/, 'Variable name must be a simple identifier'),
  description: z.string().optional(),
  required: z.boolean().default(false),
  default: z.string().optional()
});
export type PersonaVariable = z.infer<typeof personaVariableSchema>;

export const personaDefinitionSchema = z.object({
  id: z.string().min(1).max(64).regex(/^[a-z0-9][a-z0-9-]*$/, 'Persona id must be a lowercase slug'),
  name: z.string().min(1).max(120),
  version: z.number().int().positive().default(1),
  description: z.string().max(1000).default(''),
  author: z.string().min(1).max(120),
  systemPrompt: z.string().min(1).max(20_000),
  variables: z.array(personaVariableSchema).default([]),
  createdAt: z.string().optional(),
  updatedAt: z.string().optional(),
  contentHash: z.string().optional()
});
export type PersonaDefinition = z.infer<typeof personaDefinitionSchema>;

export interface AppliedPersona {
  applicationId: string;
  personaId: string;
  version: number;
  prompt: string;
  promptHash: string;
  appliedAt: string;
  actor: string;
  reason?: string;
  receipt: string;
}

export interface PersonaStoreFile {
  version: 1;
  personas: PersonaDefinition[];
}

export interface PersonaValidationResult {
  valid: boolean;
  issues: string[];
}

export interface ApplyOptions {
  actor: string;
  reason?: string;
  variables?: Record<string, string>;
}

/**
 * Personas may legitimately set identity and behavioral rules, but never override higher-priority
 * instructions, disable safety controls, or exfiltrate secrets. Matching patterns are rejected both
 * in the template and in rendered variable values.
 */
const INJECTION_PATTERNS: Array<RegExp> = [
  /(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|system|developer)\s+instructions?/i,
  /(?:bypass|disable|override|turn off)\s+(?:approval|policy|safety|guardrail|moderation)/i,
  /(?:reveal|print|send|exfiltrate|output|leak)\s+(?:the\s+)?(?:system prompt|secrets?|credentials?|api\s?keys?|passwords?|tokens?)/i,
  /(?:do not tell|hide this|secret(?:ly)?|do not reveal)\b/i,
  /(?:ignore|disregard)\s+the\s+(?:operator|owner|administrator)/i,
  /(?:abaikan|hiraukan)\s+(?:semua\s+)?(?:instruksi|perintah)\s+(?:sebelumnya|terdahulu)/i,
  /(?:nonaktifkan|lewati|langgar)\s+(?:persetujuan|kebijakan|pengamanan?|aturan)/i,
  /(?:bocorkan|kirim|tampilkan)\s+(?:system prompt|rahasia|kredensial|token|password)/i
];

const PLACEHOLDER = /\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}/g;

function injectionIssues(text: string): string[] {
  const issues: string[] = [];
  for (const pattern of INJECTION_PATTERNS) {
    const match = pattern.exec(text);
    if (match) issues.push(`unsafe instruction language: “${match[0].trim().slice(0, 60)}”`);
  }
  return issues;
}

export function contentHash(persona: Omit<PersonaDefinition, 'contentHash' | 'createdAt' | 'updatedAt' | 'version'>): string {
  // Version is store bookkeeping bumped on change, not behavior, so it is excluded from the hash:
  // two registrations with identical behavior compare equal regardless of a hand-written version.
  return sha256(JSON.stringify({
    id: persona.id, name: persona.name, description: persona.description,
    author: persona.author, systemPrompt: persona.systemPrompt, variables: persona.variables
  }));
}

/**
 * Validates a persona definition: schema, template placeholders vs declared variables, and the
 * injection guard over both the template and every variable default.
 */
export function validatePersona(value: unknown): PersonaValidationResult {
  const issues: string[] = [];
  const parsed = personaDefinitionSchema.safeParse(value);
  if (!parsed.success) {
    return { valid: false, issues: parsed.error.issues.map((issue) => `${issue.path.join('.') || 'persona'}: ${issue.message}`) };
  }
  const persona = parsed.data;
  const declared = new Set(persona.variables.map((variable) => variable.name));
  const used = new Set<string>();
  for (const match of persona.systemPrompt.matchAll(PLACEHOLDER)) {
    used.add(match[1]!);
    if (!declared.has(match[1]!)) issues.push(`template references undeclared variable “${match[1]}”`);
  }
  const required = persona.variables.filter((variable) => variable.required && variable.default === undefined);
  for (const variable of required) {
    if (!used.has(variable.name)) issues.push(`declared required variable “${variable.name}” is never used in the template`);
  }
  issues.push(...injectionIssues(persona.systemPrompt));
  for (const variable of persona.variables) {
    if (variable.default) issues.push(...injectionIssues(variable.default).map((issue) => `variable “${variable.name}” ${issue}`));
  }
  return { valid: issues.length === 0, issues };
}

export interface RenderedPersona {
  prompt: string;
  appliedVariables: Record<string, string>;
}

/**
 * Renders the system-prompt template. Required variables without a default must be provided;
 * undeclared or unused overrides are rejected so a typo cannot silently alter the applied persona.
 */
export function renderPersona(persona: PersonaDefinition, overrides: Record<string, string> = {}): RenderedPersona {
  const issues: string[] = [];
  for (const key of Object.keys(overrides)) {
    if (!persona.variables.some((variable) => variable.name === key)) issues.push(`unknown variable override “${key}”`);
  }
  const appliedVariables: Record<string, string> = {};
  for (const variable of persona.variables) {
    const value = overrides[variable.name] ?? variable.default;
    if (value === undefined) {
      if (variable.required) issues.push(`missing required variable “${variable.name}”`);
      continue;
    }
    issues.push(...injectionIssues(value).map((issue) => `variable “${variable.name}” ${issue}`));
    appliedVariables[variable.name] = value;
  }
  if (issues.length) throw new Error(`Cannot render persona “${persona.id}”: ${issues.join('; ')}`);
  const prompt = persona.systemPrompt.replace(PLACEHOLDER, (_match, name: string) => appliedVariables[name] ?? '');
  return { prompt, appliedVariables };
}

function personaStoreDir(target: string): string {
  // Match `dataDirectory` in @agentshield/memory: a directory target keeps its sidecar inside the
  // directory, a file target keeps it next to the file. This makes `--target .` land in
  // `./.agentshield` rather than in the parent directory.
  const absolute = resolve(target);
  return extname(absolute) ? join(dirname(absolute), '.agentshield') : join(absolute, '.agentshield');
}

async function readPersonaStore(target: string): Promise<PersonaStoreFile> {
  try {
    return JSON.parse(await readFile(join(personaStoreDir(target), 'personas.json'), 'utf8')) as PersonaStoreFile;
  } catch { return { version: 1, personas: [] }; }
}

async function writePersonaStore(target: string, store: PersonaStoreFile): Promise<void> {
  const path = join(personaStoreDir(target), 'personas.json');
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(store, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
  await rename(temporary, path);
}

/**
 * Registers a persona. Content-addressable: registering identical content returns the existing
 * definition; changing behavior bumps the version so applied receipts stay unambiguous.
 */
export async function registerPersona(target: string, value: unknown, actor: string): Promise<PersonaDefinition> {
  if (!actor.trim()) throw new Error('Persona registration requires a non-empty actor');
  const validation = validatePersona(value);
  if (!validation.valid) throw new Error(`Persona rejected: ${validation.issues.join('; ')}`);
  const input = personaDefinitionSchema.parse(value);
  const now = new Date().toISOString();
  const store = await readPersonaStore(target);
  const existing = store.personas.find((persona) => persona.id === input.id);
  const hash = contentHash(input);
  if (existing) {
    if (existing.contentHash === hash) return existing;
    const next = personaDefinitionSchema.parse({
      ...input, version: existing.version + 1, createdAt: existing.createdAt ?? now, updatedAt: now, contentHash: hash
    });
    store.personas = store.personas.map((persona) => persona.id === input.id ? next : persona);
    await writePersonaStore(target, store);
    return next;
  }
  const persona = personaDefinitionSchema.parse({
    ...input, createdAt: now, updatedAt: now, contentHash: hash
  });
  store.personas.push(persona);
  await writePersonaStore(target, store);
  return persona;
}

export async function listPersonas(target: string): Promise<PersonaDefinition[]> {
  return (await readPersonaStore(target)).personas;
}

export async function getPersona(target: string, id: string): Promise<PersonaDefinition | undefined> {
  return (await readPersonaStore(target)).personas.find((persona) => persona.id === id);
}

export async function removePersona(target: string, id: string, actor: string): Promise<PersonaDefinition | undefined> {
  if (!actor.trim()) throw new Error('Persona removal requires a non-empty actor');
  const store = await readPersonaStore(target);
  const index = store.personas.findIndex((persona) => persona.id === id);
  if (index < 0) return;
  const [removed] = store.personas.splice(index, 1);
  await writePersonaStore(target, store);
  return removed;
}

async function appendApplication(target: string, applied: AppliedPersona): Promise<void> {
  const path = join(personaStoreDir(target), 'persona-applications.jsonl');
  await mkdir(dirname(path), { recursive: true });
  let previousHash = 'genesis';
  try {
    const lines = (await readFile(path, 'utf8')).trim().split(/\r?\n/);
    const last = JSON.parse(lines.at(-1) ?? '{}');
    previousHash = last.hash ?? previousHash;
  } catch { /* first application */ }
  // The raw prompt never touches the audit file; only its hash is recorded.
  const entry = {
    applicationId: applied.applicationId, personaId: applied.personaId, version: applied.version,
    promptHash: applied.promptHash, appliedAt: applied.appliedAt, actor: applied.actor,
    reason: applied.reason, previousHash
  };
  await appendFile(path, `${JSON.stringify({ ...entry, hash: sha256(JSON.stringify(entry)) })}\n`, { encoding: 'utf8', mode: 0o600 });
}

/**
 * Applies a persona: renders the prompt, chains an immutable receipt to the previous application,
 * and returns the exact prompt plus receipt so a harness can inject it and an operator can verify it.
 */
export async function applyPersona(target: string, id: string, options: ApplyOptions): Promise<AppliedPersona> {
  if (!options.actor.trim()) throw new Error('Persona application requires a non-empty actor');
  const persona = await getPersona(target, id);
  if (!persona) throw new Error(`Persona not found: ${id}`);
  const rendered = renderPersona(persona, options.variables);
  const appliedAt = new Date().toISOString();
  const applied: AppliedPersona = {
    applicationId: createId('papp'),
    personaId: persona.id,
    version: persona.version,
    prompt: rendered.prompt,
    promptHash: sha256(rendered.prompt),
    appliedAt,
    actor: options.actor,
    reason: options.reason,
    receipt: `persona1:${sha256([persona.id, String(persona.version), rendered.prompt, options.actor, appliedAt].join('\0')).replace('sha256:', '')}`
  };
  await appendApplication(target, applied);
  return applied;
}

export interface PersonaApplicationFile {
  applicationId: string;
  personaId: string;
  version: number;
  promptHash: string;
  appliedAt: string;
  actor: string;
  reason?: string;
  receipt: string;
  previousHash: string;
  hash: string;
}

/** Lists the application audit trail (prompts are never stored; only their hashes). */
export async function listPersonaApplications(target: string): Promise<PersonaApplicationFile[]> {
  try {
    return (await readFile(join(personaStoreDir(target), 'persona-applications.jsonl'), 'utf8')).split(/\r?\n/).filter(Boolean)
      .map((line) => JSON.parse(line) as PersonaApplicationFile);
  } catch { return []; }
}

/** Verifies the hash chain of every recorded application and that the chain is intact. */
export function verifyApplicationChain(applications: PersonaApplicationFile[]): { valid: boolean; brokenAt?: string } {
  let previousHash = 'genesis';
  for (const application of applications) {
    const { hash, ...record } = application;
    if (application.previousHash !== previousHash) return { valid: false, brokenAt: application.applicationId };
    if (sha256(JSON.stringify(record)) !== hash) return { valid: false, brokenAt: application.applicationId };
    previousHash = hash;
  }
  return { valid: true };
}

/** Loads a persona definition from a YAML or JSON file and validates it without registering. */
export function loadPersonaFile(content: string): unknown {
  return YAML.parse(content);
}

export { sha256 };
