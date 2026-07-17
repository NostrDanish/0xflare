# 0xFlare Public Square

Privacy-hardened general-purpose Nostr relay (Nosflare fork). Part of the 0xPrivacy relay family.

## Profile differences vs DM Vault
- Accepts general kinds (1,6,7,11,12...) + DMs (4,1059). Relay-list (10002) kept for identity.
- NIP-42 auth **forced** — no anonymous writes.
- Per-pubkey anti-spam hash (NOT global) so public discourse isn't silenced by one phrase.
- Rate limits: 10 events/min/pubkey, 50 req/min.
- Prunes volatile content at 9GB, preserves profile (0)/contact (3)/relay-list (10002).

## Honest trade-off
Cloudflare Workers see client IP + TLS. For metadata resistance pair with Tor proxy
(see DM Vault `ghost/` pattern adapted here). Build is fast + cheap, not anonymous at network layer.

## Deploy
1. `npm install`
2. `wrangler d1 create 0xflare-general` -> paste UUID into wrangler.toml
3. `npm run build`
4. `wrangler deploy`
5. Visit relay URL over HTTP once to init D1.
