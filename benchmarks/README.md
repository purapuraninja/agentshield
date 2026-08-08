# Scanner benchmark

Run the deterministic generated-corpus benchmark from the repository root:

```bash
pnpm benchmark:scanner
pnpm benchmark:scanner -- --files 10000 --budget-ms 300000 --json
```

The default gate creates 10,000 small safe TypeScript files outside the repository, scans them, and
requires every file to complete without parser gaps within five minutes. Temporary fixtures are
removed after the run.

Results vary with CPU, storage, antivirus, Node version, and filesystem cache. Release evidence must
record those environment details; a local pass is not a substitute for the documented 4-vCPU
reference-machine run.
