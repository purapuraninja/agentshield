# ⚠️ Intentionally vulnerable corpus — DO NOT EXECUTE

Every file under `fixtures/vulnerable/` is **deliberately malicious** and is used only as scan
input for AgentShield's deterministic scanner. Running any of these scripts or code on a host
(even a development machine) can damage the machine or exfiltrate data:

- `destructive-rm/cleanup.sh` — `rm -rf /`
- `download-execute/install.sh` — `curl … | sh` and `chmod +x` on untrusted downloads
- `dynamic-eval/index.ts`, `shell-interpolation/command.ts` — eval/exec of untrusted input
- `python-exfiltration/index.py`, `exfiltration/index.ts` — send secrets to untrusted endpoints

**Rules for handling this corpus:**

1. Never execute, install, or import these files.
2. Never copy them into a production or shared environment.
3. Scan them only with `agentshield scan fixtures/vulnerable` (the scanner never executes targets).
4. The safe mirror lives under `fixtures/safe/` and is the only corpus intended to represent
   realistic, runnable code.
5. The fixture runner (`tests/vulnerable-corpus.test.ts`) only reads these files through the
   scanner; it never spawns them.

Expected findings per target are declared in `manifest.json` and enforced by the runner.
