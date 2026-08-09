// Shell interpolation fixture: builds a shell command from user input (AS-SC-010).
import { exec } from 'node:child_process';

export function listDirectory(userPath: string): void {
  exec(`ls -la ${userPath}`);
}
