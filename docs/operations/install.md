# Install, upgrade, and uninstall

AgentShield is a local-first CLI. It never uploads target content, memory, or telemetry in the
Community edition.

## Requirements

- Node.js 22.13 or newer.
- (For building from source) Corepack-enabled pnpm, pinned via `packageManager`.

## Install from npm

```bash
npm install -g agentshield
agentshield --version
```

## Build from source

```bash
git clone https://github.com/agentshield/agentshield.git
cd agentshield
corepack pnpm install
corepack pnpm build
node packages/cli/dist/cli.cjs --version
```

For development use `corepack pnpm dev -- scan ./my-skill`.

## Shell completions

Print a completion script and source it, or write it to your completion directory.

```bash
# bash
agentshield completion bash > /etc/bash_completion.d/agentshield
# or for a single user:
agentshield completion bash >> ~/.bashrc && source ~/.bashrc

# zsh
agentshield completion zsh > "${fpath[1]}/_agentshield"

# fish
agentshield completion fish > ~/.config/fish/completions/agentshield.fish
```

## Man page

Install the bundled man page:

```bash
install -Dm644 docs/operations/agentshield.1 /usr/local/share/man/man1/agentshield.1
mandb
man agentshield
```

## Agent personas

Personas are trusted, versioned system-prompt templates with declared variables. Registering
validates structure; applying renders the prompt and records an immutable, hash-chained receipt in
`.agentshield/persona-applications.jsonl` (the raw prompt is never stored — only its hash). The
injection scanner is advisory: operator-owned personas are never rejected for content, only for
structural problems.

Register and apply a persona:

```bash
# Register from a YAML definition (see fixtures/safe/personas/)
agentshield persona create fixtures/safe/personas/code-reviewer.yaml --actor platform-team

# Validate a definition without registering
agentshield persona verify fixtures/safe/personas/security-analyst.yaml

# Render or apply with variable overrides
agentshield persona render code-reviewer --set focus=secrets
agentshield persona apply code-reviewer --actor deploy-bot --reason "release 1.4" --set focus=secrets

# Inspect the application audit trail
agentshield persona applications
```

Assign a persona to an AI model. This applies the persona (recording a receipt) and emits a
provider-native request (OpenAI `messages`, Anthropic `system`, Gemini `systemInstruction`, or
generic) — no network call is made:

```bash
agentshield persona model code-reviewer \
  --provider openai --model gpt-4o \
  --actor deploy-bot --reason "release 1.4" \
  --set focus=secrets --max-tokens 512 \
  --output request.json
```

Verify the persona actually behaves correctly by sending a real test message to the model with
**your own API key** (read from `OPENAI_API_KEY`/`ANTHROPIC_API_KEY`/`GEMINI_API_KEY`/
`MISTRAL_API_KEY`, or passed with `--api-key`; never stored). The apply still records a receipt,
then the provider is called and the model's reply is shown:

```bash
# OpenAI / Anthropic / Gemini / Mistral — set the matching env var first
export OPENAI_API_KEY=sk-…
agentshield persona chat code-reviewer \
  --provider openai --model gpt-4o \
  --actor deploy-bot --message "Halo, kamu persona apa?" \
  --set focus=secrets

# Local Ollama (no key required)
agentshield persona chat code-reviewer \
  --provider ollama --model llama3.1 --actor deploy-bot --message "Halo"

# Self-hosted OpenAI-compatible endpoint
agentshield persona chat code-reviewer \
  --provider generic --model local-model --base-url http://127.0.0.1:8000/v1/chat/completions \
  --actor deploy-bot --message "Halo"
```

In an agent harness, apply the persona and record it into the runtime evidence graph in one call:

```ts
import { AgentShieldGate, applyPersonaToModel } from '@agentshield/runtime';

const gate = new AgentShieldGate({ policies });
const { applied, request, gateReceipt, event } = await applyPersonaToModel(
  '.', 'code-reviewer',
  { actor: 'deploy-bot', provider: 'openai', model: 'gpt-4o', variables: { focus: 'secrets' } },
  { gate, context: { traceId: 'run-42', actor: 'deploy-bot' } }
);
// request.request holds the system portion (see request.injectedAs); append your conversation
// messages and send it. event.type === 'persona.applied'; gateReceipt is the signed as1: receipt.
```

## Upgrade

```bash
npm update -g agentshield
```

When building from source, pull the latest tag and rebuild:

```bash
git pull --ff-only
corepack pnpm install
corepack pnpm build
```

Local data in `.agentshield/` (memory cache, quarantine snapshots, runtime events, telemetry
consent) is forward-compatible within a major version. The memory assessment cache is keyed by a
detector version, so a detector upgrade safely invalidates only the affected records.

## Uninstall

```bash
npm uninstall -g agentshield
```

Remove the local data directory if you no longer need cached reports, quarantine snapshots, or
consent receipts. The source store is never modified or deleted by AgentShield, so this only removes
AgentShield-owned artifacts:

```bash
rm -rf .agentshield
```

Optionally remove the installed man page and completion script added above.
