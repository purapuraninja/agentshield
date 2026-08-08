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
