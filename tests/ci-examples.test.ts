import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

const ROOT = resolve('.');

async function yaml(path: string): Promise<Record<string, unknown>> {
  return parse(await readFile(resolve(ROOT, path), 'utf8')) as Record<string, unknown>;
}

describe('reusable CI artifacts', () => {
  it('ships a valid composite GitHub Action', async () => {
    const action = await yaml('.github/actions/scan/action.yml');
    expect(action.name).toBe('AgentShield scan');
    const runs = action.runs as { using: string; steps: unknown[] };
    expect(runs.using).toBe('composite');
    expect(runs.steps.length).toBeGreaterThan(0);
    const inputs = action.inputs as Record<string, { required?: boolean; default?: string }>;
    expect(inputs.target!.required).toBe(true);
    expect(inputs['sarif-path']!.default).toBe('agentshield.sarif');
  });

  it('provides a GitHub Actions example that reuses the action', async () => {
    const workflow = await yaml('docs/operations/github-action-example.yml');
    expect(workflow.on).toBeTruthy();
    const jobs = workflow.jobs as Record<string, { steps: Array<{ uses?: string; name?: string }> }>;
    expect(jobs.scan).toBeDefined();
    expect(jobs.scan!.steps.some((step) => step.uses?.includes('actions/scan'))).toBe(true);
  });

  it('provides a GitLab CI example with a scan stage', async () => {
    const gitlab = await yaml('docs/operations/ci-gitlab.yml');
    const job = (gitlab['agentshield:scan'] as { stage: string; script: string[] }).stage;
    expect(job).toBe('test');
  });

  it('provides an Azure Pipelines example with scan steps', async () => {
    const azure = await yaml('docs/operations/ci-azure-pipelines.yml');
    const jobs = azure.jobs as Array<{ steps: Array<{ script?: string; displayName?: string }> }>;
    expect(jobs.length).toBe(1);
    expect(jobs[0]!.steps.some((step) => step.script?.includes('agentshield scan'))).toBe(true);
  });

  it('provides a Jenkins declarative pipeline example', async () => {
    const jenkins = await readFile(resolve(ROOT, 'docs/operations/ci-jenkinsfile'), 'utf8');
    expect(jenkins).toContain('pipeline');
    expect(jenkins).toContain('agentshield scan');
    expect(jenkins).toContain('archiveArtifacts');
  });
});
