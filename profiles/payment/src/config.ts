import { RelayInfo } from './types';

// 0xFlare - PayGate profile (privacy-hardened Nosflare fork)
// Payment relay: stores zap events (NIP-57) + DMs. Pay-to-relay via Lightning.
// 0xPrivacy: no KYC, no logging, self-hosted Lightning node or LNBits.

export const relayNpub = "npub13dl38k366f09eah0w3748zvd0x8ez7mpvxs6rqv4025gsan656zsn3d3vd"; // 0xDevBot
export const PAY_TO_RELAY_ENABLED = true; // PayGate is paid
export const RELAY_ACCESS_PRICE_SATS = 1000; // one-time admission in sats (msats in fees)

export const AUTH_REQUIRED = true; // NIP-42 forced
export const AUTH_TIMEOUT_MS = 300000;

export const relayInfo: RelayInfo = {
  name: "0xFlare PayGate",
  description: "Privacy-hardened Nostr payment relay. Zap events + DMs. Lightning pay-to-relay. 0xPrivacy.",
  pubkey: "8b7f13da3ad25e5cf6ef747d53898d798f917b6161a1a181957aa888767aa685",
  contact: "dev@0xprivacy.org",
  supported_nips: [1, 4, 17, 40, 42, 57],
  software: "https://github.com/NostrDanish/0xflare",
  version: "1.0.0-payment",
  limitation: {
    auth_required: AUTH_REQUIRED,
    payment_required: PAY_TO_RELAY_ENABLED,
    restricted_writes: PAY_TO_RELAY_ENABLED
  },
  payments_url: "https://your-lnbits-or-lnd/paywall",
  fees: {
    admission: [{ amount: RELAY_ACCESS_PRICE_SATS * 1000, unit: "msats" }]
  }
};

// PayGate: only payment + DM kinds. No notes/feeds.
export const allowedEventKinds = new Set<number>([4, 1059, 9734, 9735, 13194, 13196]);
export const blockedEventKinds = new Set<number>([0, 1, 2, 3, 6, 7, 10002, 22242]);

export const blockedPubkeys = new Set<string>([]);
export const allowedPubkeys = new Set<string>([]);
export const blockedContent = new Set<string>([]);

export const checkValidNip05 = false;
export const blockedNip05Domains = new Set<string>([]);
export const allowedNip05Domains = new Set<string>([]);
export const blockedTags = new Set<string>([]);
export const allowedTags = new Set<string>([]);

// Zap events are unique - global dup check prevents replay
export const enableAntiSpam = true;
export const enableGlobalDuplicateCheck = true;
export const antiSpamKinds = new Set([9734, 9735]);

export const PUBKEY_RATE_LIMIT = { rate: 5 / 60000, capacity: 5 };
export const REQ_RATE_LIMIT = { rate: 30 / 60000, capacity: 30 };
export const excludedRateLimitKinds = new Set<number>([1059]);

// Payment relay: keep zap receipts long-term, prune ephemeral
export const DB_PRUNING_ENABLED = true;
export const DB_SIZE_THRESHOLD_GB = 9;
export const DB_PRUNE_BATCH_SIZE = 2000;
export const DB_PRUNE_TARGET_GB = 8;
export const pruneProtectedKinds = new Set<number>([9735]); // keep zap receipts

export function isPubkeyAllowed(pubkey: string): boolean {
  if (allowedPubkeys.size > 0 && !allowedPubkeys.has(pubkey)) return false;
  return !blockedPubkeys.has(pubkey);
}
export function isEventKindAllowed(kind: number): boolean {
  if (allowedEventKinds.size > 0 && !allowedEventKinds.has(kind)) return false;
  return !blockedEventKinds.has(kind);
}
export function containsBlockedContent(event: any): boolean {
  const lc = (event.content || "").toLowerCase();
  const ltags = event.tags.map((t: string[]) => t.join("").toLowerCase());
  for (const b of blockedContent) {
    const bl = b.toLowerCase();
    if (lc.includes(bl) || ltags.some((t: string) => t.includes(bl))) return true;
  }
  return false;
}
export function isTagAllowed(tag: string): boolean {
  if (allowedTags.size > 0 && !allowedTags.has(tag)) return false;
  return !blockedTags.has(tag);
}

// --- Cashu admission (most private: no LN correlation) ---
export const ADMISSION_VIA_CASHU = true; // set true to accept Cashu ecash instead of LN
export const MINT_URL = "https://test.mint.cashu.space"; // your Cashu mint
export const ADMISSION_SATS = 1000; // required token value (sum of proofs)
