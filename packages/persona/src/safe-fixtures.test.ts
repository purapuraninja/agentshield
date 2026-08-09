import { readFile, readdir } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadPersonaFile, renderPersona, validatePersona, type PersonaDefinition } from './index.js';

const SAFE_PERSONAS_ROOT = resolve('fixtures/safe/personas');

describe('maintained safe persona fixtures', () => {
  it('every fixtures/safe/personas/*.yaml is structurally valid and free of injection warnings', async () => {
    const names = (await readdir(SAFE_PERSONAS_ROOT)).filter((name) => name.endsWith('.yaml'));
    expect(names.length).toBeGreaterThanOrEqual(2);
    for (const name of names) {
      const definition = loadPersonaFile(await readFile(join(SAFE_PERSONAS_ROOT, name), 'utf8'));
      const result = validatePersona(definition);
      expect(result.valid, `${name} should be structurally valid: ${result.issues.join('; ')}`).toBe(true);
      // The advisory scanner must stay silent on the maintained safe corpus, so a regression in the
      // injection patterns cannot silently flag operator-owned fixtures as suspicious.
      expect(result.warnings, `${name} should not produce advisory warnings`).toEqual([]);
    }
  });

  it('renders every safe persona with declared defaults and no warnings', async () => {
    const names = (await readdir(SAFE_PERSONAS_ROOT)).filter((name) => name.endsWith('.yaml'));
    for (const name of names) {
      const definition = loadPersonaFile(await readFile(join(SAFE_PERSONAS_ROOT, name), 'utf8')) as PersonaDefinition;
      const placeholders = Object.fromEntries(
        definition.variables.filter((variable) => variable.required && variable.default === undefined)
          .map((variable) => [variable.name, 'example'])
      );
      const rendered = renderPersona(definition, placeholders);
      expect(rendered.prompt.length).toBeGreaterThan(0);
      expect(rendered.warnings).toEqual([]);
    }
  });
});
