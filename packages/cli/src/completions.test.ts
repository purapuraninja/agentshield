import { describe, expect, it } from 'vitest';
import { SUPPORTED_SHELLS, completionScript, isSupportedShell } from './completions.js';

describe('shell completions', () => {
  it('ships a completion script for every supported shell', () => {
    for (const shell of SUPPORTED_SHELLS) {
      const script = completionScript(shell);
      expect(script.length).toBeGreaterThan(50);
      expect(script).toContain('agentshield');
    }
  });

  it('generates a bash script that registers a completion function', () => {
    expect(completionScript('bash')).toContain('complete -F _agentshield_completion agentshield');
    expect(completionScript('bash')).toContain('scan');
  });

  it('generates a zsh #compdef script', () => {
    expect(completionScript('zsh')).toContain('#compdef agentshield');
  });

  it('generates a fish script using complete -c', () => {
    expect(completionScript('fish')).toContain('complete -c agentshield');
  });

  it('validates supported shells', () => {
    expect(isSupportedShell('bash')).toBe(true);
    expect(isSupportedShell('powershell')).toBe(false);
  });
});
