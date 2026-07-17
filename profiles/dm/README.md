# 0xFlare DM Vault

Privacy-hardened Nostr relay (fork of Nosflare) that accepts **only encrypted DMs**:
kind 4 (NIP-04) and kind 1059 (NIP-17 giftwrap). Part of the 0xPrivacy relay family.

## Privacy hardening vs stock Nosflare
- NIP-42 auth **forced** — no anonymous writes.
- Kind allowlist locked to `4, 1059`. Profile (0), contacts (3), relay list (10002) blocked.
- Aggressive D1 pruning (target 4GB, no protected kinds) — DMs are ephemeral.
- CF observability logs **off**. No analytics, no NIP-05 tracking.
- Global anti-spam hash on ciphertext prevents replay floods.

## Honest trade-off
Cloudflare Workers terminate TLS and see client IP. For true metadata resistance,
deploy the companion Tor hidden service (see `ghost/` profile). This relay hardens
content + write policy, not network-level anonymity.

## Deploy
1. `npm install`
2. Create D1 database: `wrangler d1 create 0xflare-dm` and paste UUID into `wrangler.toml`.
3. Replace `REPLACE_DEVBOT_HEX` in `src/config.ts` with your relay pubkey hex.
4. `npm run build` (produces worker.js)
5. `wrangler deploy`
6. Visit relay URL once over HTTP to init D1 tables.

## Connect
Add `wss://your-domain.workers.dev` to your Nostr client relay list.
Test with `/root/nip17_send.py` (0xDevBot -> NostrDanish giftwrap).

## Profiles
- `./` — Cloudflare Workers DM Vault (Nosflare fork, fast, but CF sees IP).
- `./ghost/` — Tor-hidden strfry DM Vault (true metadata resistance, slower).
