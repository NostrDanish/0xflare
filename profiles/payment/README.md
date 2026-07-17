# 0xFlare PayGate

Privacy-hardened Nostr payment relay (Nosflare fork). Part of the 0xPrivacy relay family.

## What it does
- Stores Lightning zap events (NIP-57: 9734 request, 9735 receipt) + DMs (4,1059).
- Pay-to-relay: admission via Lightning (1,000 sats default). No KYC, no accounts.
- Pair with self-hosted LNBits or LND for the `/payments` endpoint.

## Hardening
- NIP-42 auth forced.
- Kind allowlist: 4, 1059, 9734, 9735, 13194, 13196. No notes/feeds/contacts.
- Global dup hash on zap events prevents receipt replay.
- CF observability OFF. No analytics.
- Zap receipts (9735) preserved; ephemeral pruned.

## Lightning integration (you provide)
Set `payments_url` in config.ts to your LNBits paywall or LND invoice endpoint.
The relay checks payment proof before accepting writes (extend index.ts handleEvent
to query your LN backend on first publish per pubkey).

## Deploy
1. `npm install`
2. `wrangler d1 create 0xflare-payment` -> paste UUID into wrangler.toml
3. `npm run build`
4. `wrangler deploy`
5. Visit relay URL over HTTP once to init D1.

## Lightning wiring (implemented)
- `src/index.ts` `checkPaid(env, pubkey)` calls `${PAYMENT_URL}/api/v1/paywall/check/${pubkey}` with `X-Api-Key: ${LN_API_KEY}`.
- On every EVENT, if `PAY_TO_RELAY_ENABLED`, the relay rejects with `payment required: <url>` until the pubkey is admitted.
- Set secrets via `wrangler secret put PAYMENT_URL` and `wrangler secret put LN_API_KEY` (or `.dev.vars` locally).
- Compatible with LNBits paywall extension. For LND, swap the fetch for an gRPC/REST invoice lookup.
- Dev mode: if `PAYMENT_URL` is unset, relay allows all (logs warning). Never ship like that.

## Cashu admission (most private mode)
- Set `ADMISSION_VIA_CASHU = true` in config.ts (default).
- Client sends a `CASHU` websocket message with ecash proofs minted at `MINT_URL`.
- `cashu.ts` validates proof format, checks total >= ADMISSION_SATS, then swaps
  (burns) them with the mint via POST /v1/swap. No LN correlation = no payment graph link.
- Admitted pubkeys cached in-memory. No account, no email, no IP log beyond CF.
- Swap `MINT_URL` to your own Cashu mint for full sovereignty.
- Fallback: set ADMISSION_VIA_CASHU=false to use Lightning LNBits instead.
