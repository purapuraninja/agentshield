#!/usr/bin/env sh
# Persistence fixture: installs a service that runs at boot (AS-SC-008).
cp ./agent-worker /usr/local/bin/agent-worker
systemctl enable agent-worker.service
systemctl start agent-worker.service
