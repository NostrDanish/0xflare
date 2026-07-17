# 0xFlare

Privacy-hardened fork of [Nosflare](https://github.com/fiatjaf/nosflare) — a Cloudflare Workers + D1 Nostr relay.

Three relay profiles, each in `profiles/`:

| Profile | Purpose | Kinds |
|---------|---------|-------|
| `dm`    | DM Vault — sealed NIP-04/NIP-17 only | 4, 1059 |
| `general` | Public relay with anti-spam | 0, 1, 2, 3, 7, 10002, ... |
| `payment` | Pay-to-relay (Lightning + Cashu) | 9734, 9735, 4, 1059 |

Plus a Tor-hidden `ghost` variant (strfry + nginx + tor hidden service).

## Deploy

```
cd profiles/<name>
./deploy.sh
```

## Privacy posture

- DM Vault: NIP-42 forced auth, ephemeral prune, observability OFF
- General: per-pubkey anti-spam, preserves profile/relay-list events
- Payment: global dup-hash on zaps, Cashu ecash admission (no LN correlation)

0xPrivacy — privacy is a human right.
