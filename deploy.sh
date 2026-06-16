#!/bin/bash
# Auto-deploy script — called by webhook on push
set -e

APP_DIR="/opt/argos-remote-gateway"
REPO="https://github.com/mupa-desenvolvimento/argos_gateway.git"

echo "[deploy] $(date) — Starting deploy..."

# If first time, clone; otherwise pull
if [ ! -d "$APP_DIR/.git" ]; then
  echo "[deploy] Cloning repo..."
  rm -rf "$APP_DIR"
  git clone "$REPO" "$APP_DIR"
else
  echo "[deploy] Pulling latest..."
  cd "$APP_DIR"
  git fetch origin
  git reset --hard origin/main
fi

cd "$APP_DIR"

echo "[deploy] Installing dependencies..."
npm install --production

echo "[deploy] Restarting service..."
systemctl restart argos-remote

sleep 2
if systemctl is-active --quiet argos-remote; then
  echo "[deploy] ✓ Service running"
else
  echo "[deploy] ✗ Service failed!"
  systemctl status argos-remote --no-pager
  exit 1
fi

echo "[deploy] Done at $(date)"
