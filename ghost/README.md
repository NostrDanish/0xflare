# Ghost Vault - Tor-Hidden Nostr DM Relay

True network-level metadata resistance for the 0xFlare DM Vault.

Stack: strfry relay -> nginx (ws upgrade) -> Tor hidden service.
No Cloudflare, no clearnet IP. Clients connect via .onion only.

## Run
```bash
cd ghost
docker compose up -d
docker compose exec tor cat /var/lib/tor/hidden_service/hostname
# => abcdefg...xyz.onion
```
Add `ws://abcdefg...xyz.onion` to your Nostr client.
Use a Tor-capable client (or proxy) — e.g. Damus via Orbot, or
`proxychains` + websocat for testing.

## Privacy
- No TLS termination by us; Tor provides end-to-end hidden routing.
- strfry config restricts to DM kinds (4,1059,22242).
- Nothing leaves the docker network except via Tor.

## Honest limits
- .onion is slow; fine for DMs, not high-volume feeds.
- You still trust the strfry build. Pin the image digest for supply-chain safety.
