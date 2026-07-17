#!/usr/bin/env bash
# 0xFlare DM Vault - one-click-ish deploy
set -e
echo "[1/5] npm install"
npm install
echo "[2/5] create D1 database (copy the UUID it prints)"
wrangler d1 create 0xflare-general
echo "[3/5] paste the UUID into wrangler.toml database_id, then press enter"
read -r _
echo "[4/5] build worker.js"
npm run build
echo "[5/5] deploy"
wrangler deploy
echo "DONE. Visit your relay URL over HTTP once to init D1."
