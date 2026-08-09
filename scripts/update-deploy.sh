#!/usr/bin/env bash
# AgentShield VPS update script — run on the VPS to deploy the latest main.
#
#   bash scripts/update-deploy.sh [compose-file]
#
# Defaults to deploy/compose/docker-compose.shield.yml (nginx-backed VPS layout). Pass another
# compose file as the first argument if needed. Safe to re-run: pulls fast-forward only and
# rebuilds only what changed. The .env file in deploy/compose/ is never touched.
set -euo pipefail

COMPOSE="${1:-deploy/compose/docker-compose.shield.yml}"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_DIR="$(dirname "$REPO_DIR/$COMPOSE")"

echo "==> AgentShield update @ $(date -u +%Y-%m-%dT%H:%M:%SZ)"
cd "$REPO_DIR"

if [ -n "$(git status --porcelain)" ]; then
  echo "!! Working tree is not clean. Aborting to avoid overwriting local changes."
  echo "   Fix or stash local changes first, then re-run."
  exit 1
fi

echo "==> Pulling latest main"
git pull --ff-only origin main

echo "==> Rebuilding stack ($COMPOSE)"
cd "$COMPOSE_DIR"
docker compose -f "$(basename "$COMPOSE")" up -d --build

echo "==> Waiting for API health"
for attempt in $(seq 1 15); do
  sleep 2
  if curl -fsS http://127.0.0.1:8082/health >/dev/null 2>&1; then
    echo "==> API healthy after ${attempt}0s"
    curl -s http://127.0.0.1:8082/health
    echo
    exit 0
  fi
done

echo "!! API did not become healthy within 30s. Check logs:"
echo "    docker compose -f deploy/compose/docker-compose.shield.yml logs api"
exit 1
