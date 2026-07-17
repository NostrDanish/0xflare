import { RelayInfo } from './types';

// 0xFlare - DM Vault profile (privacy-hardened Nosflare fork)
// Accepts ONLY encrypted DM kinds. Blocks profile/contact leakage.

export const relayNpub = "npub13dl38k366f09eah0w3748zvd0x8ez7mpvxs6rqv4025gsan656zsn3d3vd"; // 0xDevBot
export const PAY_TO_RELAY_ENABLED = false; // DM vault is free, auth-gated
export const RELAY_ACCESS_PRICE_SATS = 0;

export const AUTH_REQUIRED = true; // NIP-42 forced — no anonymous writes
export const AUTH_TIMEOUT_MS = 300000; // 5 min challenge

export const relayInfo: RelayInfo = {
  name: "0xFlare DM Vault",
  description: "Privacy-hardened Nostr DM relay (kind 4 + 1059 only). 0xPrivacy.",
  pubkey: "8b7f13da3ad25e5cf6ef747d53898d798f917b6161a1a181957aa888767aa685",
  contact: "dev@0xprivacy.org",
  supported_nips: [1, 4, 17, 40, 42],
  software: "https://github.com/NostrDanish/0xflare",
  version: "1.0.0-dm",
  limitation: {
    auth_required: AUTH_REQUIRED,
    payment_required: false,
    restricted_writes: true
  }
};

// DM-only: allow ONLY kind 4 (NIP-04) and 1059 (NIP-17 giftwrap)
export const allowedEventKinds = new Set<number>([4, 1059]);
export const blockedEventKinds = new Set<number>([
  0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 10002, 22242
]);

export const blockedPubkeys = new Set<string>([]);
export const allowedPubkeys = new Set<string>([]);
export const blockedContent = new Set<string>([]);

export const checkValidNip05 = false;
export const blockedNip05Domains = new Set<string>([]);
export const allowedNip05Domains = new Set<string>([]);
export const blockedTags = new Set<string>([]);
export const allowedTags = new Set<string>([]);

// Anti-spam: DM content is opaque ciphertext, so global content-hash dup still useful
export const enableAntiSpam = true;
export const enableGlobalDuplicateCheck = true;
export const antiSpamKinds = new Set([4, 1059]);

// Rates: DMs are low-volume
export const PUBKEY_RATE_LIMIT = { rate: 5 / 60000, capacity: 5 };
export const REQ_RATE_LIMIT = { rate: 30 / 60000, capacity: 30 };
export const excludedRateLimitKinds = new Set<number>([]);

// Ephemeral DM vault: aggressive pruning
export const DB_PRUNING_ENABLED = true;
export const DB_SIZE_THRESHOLD_GB = 5;
export const DB_PRUNE_BATCH_SIZE = 2000;
export const DB_PRUNE_TARGET_GB = 4;
// Do NOT preserve kind 0/3 (blocked anyway). DMs auto-expire.
export const pruneProtectedKinds = new Set<number>([]);

// Helper functions (same as stock)
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
