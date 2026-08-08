import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

const ROOT = resolve('.');

describe('cli documentation artifacts', () => {
  it('ships a roff man page covering the main commands and exit codes', async () => {
    const man = await readFile(resolve(ROOT, 'docs/operations/agentshield.1'), 'utf8');
    expect(man).toContain('.TH AGENTSHIELD');
    expect(man).toContain('scan');
    expect(man).toContain('memory audit');
    expect(man).toContain('telemetry');
    expect(man).toMatch(/EXIT CODES/);
  });

  it('ships install, upgrade, uninstall, completion, and man page guidance', async () => {
    const install = await readFile(resolve(ROOT, 'docs/operations/install.md'), 'utf8');
    expect(install).toMatch(/Install/i);
    expect(install).toMatch(/Upgrade/i);
    expect(install).toMatch(/Uninstall/i);
    expect(install).toContain('completion');
    expect(install).toContain('man agentshield');
  });
});

describe('VPS deployment artifacts', () => {
  it('ships a VPS docker-compose with API and Caddy services', async () => {
    const compose = parse(await readFile(resolve(ROOT, 'deploy/compose/docker-compose.vps.yml'), 'utf8')) as Record<string, unknown>;
    const services = compose.services as Record<string, { build?: { dockerfile: string }; ports?: string[]; environment?: Record<string, string> }>;
    expect(services.api).toBeDefined();
    expect(services.caddy).toBeDefined();
    expect(services.api!.ports).toBeUndefined();
    expect(services.caddy!.ports).toEqual(['80:80', '443:443']);
    expect(services.api!.environment?.AGENTSHIELD_API_TOKEN).toBe('${AGENTSHIELD_API_TOKEN}');
  });

  it('ships a Caddyfile that proxies the API and serves the dashboard', async () => {
    const caddyfile = await readFile(resolve(ROOT, 'deploy/docker/Caddyfile'), 'utf8');
    expect(caddyfile).toContain('reverse_proxy api:4141');
    expect(caddyfile).toContain('file_server');
    expect(caddyfile).toContain('Strict-Transport-Security');
  });

  it('ships an environment template with required variables', async () => {
    const env = await readFile(resolve(ROOT, 'deploy/compose/.env.example'), 'utf8');
    expect(env).toContain('AGENTSHIELD_DOMAIN');
    expect(env).toContain('AGENTSHIELD_API_TOKEN');
    expect(env).toContain('AGENTSHIELD_ALLOWED_ORIGINS');
  });

  it('ships a deployment runbook covering token generation and verification', async () => {
    const runbook = await readFile(resolve(ROOT, 'docs/operations/deploy-vps.md'), 'utf8');
    expect(runbook).toContain('--generate-token');
    expect(runbook).toContain('curl');
    expect(runbook).toMatch(/security checklist/i);
  });
});
