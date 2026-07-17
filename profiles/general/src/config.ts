import { RelayInfo } from './types';

// 0xFlare - Public Square profile (privacy-hardened Nosflare fork)
// General-purpose relay. NIP-42 auth forced. Anti-spam + rate-limit. No kind 0/3 leak to third parties.

export const relayNpub = "npub13dl38k366f09eah0w3748zvd0x8ez7mpvxs6rqv4025gsan656zsn3d3vd"; // 0xDevBot
export const PAY_TO_RELAY_ENABLED = false;
export const RELAY_ACCESS_PRICE_SATS = 0;

export const AUTH_REQUIRED = true; // NIP-42 forced
export const AUTH_TIMEOUT_MS = 300000;

export const relayInfo: RelayInfo = {
  name: "0xFlare Public Square",
  description: "Privacy-hardened general Nostr relay. 0xPrivacy. Auth-gated, anti-spam.",
  pubkey: "8b7f13da3ad25e5cf6ef747d53898d798f917b6161a1a181957aa888767aa685",
  contact: "dev@0xprivacy.org",
  supported_nips: [1, 2, 4, 5, 9, 11, 12, 15, 16, 17, 20, 22, 25, 33, 40, 42, 57],
  software: "https://github.com/NostrDanish/0xflare",
  version: "1.0.0-general",
  limitation: {
    auth_required: AUTH_REQUIRED,
    payment_required: false,
    restricted_writes: true
  }
};

// Public square: general + DM kinds, but NOT relay-list spam vectors
export const allowedEventKinds = new Set<number>([1, 4, 5, 6, 7, 9, 11, 12, 13, 15, 16, 17, 20, 22, 25, 33, 42, 57, 1059]);
export const blockedEventKinds = new Set<number>([1064, 22242]); // block raw auth kind from being stored

export const blockedPubkeys = new Set<string>([]);
export const allowedPubkeys = new Set<string>([]);
export const blockedContent = new Set<string>([]);

export const checkValidNip05 = false;
export const blockedNip05Domains = new Set<string>([]);
export const allowedNip05Domains = new Set<string>([]);
export const blockedTags = new Set<string>([]);
export const allowedTags = new Set<string>([]);

export const enableAntiSpam = true;
export const enableGlobalDuplicateCheck = false; // per-pubkey dup only (public feed, not global silence)
export const antiSpamKinds = new Set([1, 4, 6, 7, 17, 1059]);

export const PUBKEY_RATE_LIMIT = { rate: 10 / 60000, capacity: 10 };
export const REQ_RATE_LIMIT = { rate: 50 / 60000, capacity: 50 };
export const excludedRateLimitKinds = new Set<number>([1059]);

// Public square: keep identity events, prune volatile content
export const DB_PRUNING_ENABLED = true;
export const DB_SIZE_THRESHOLD_GB = 9;
export const DB_PRUNE_BATCH_SIZE = 2000;
export const DB_PRUNE_TARGET_GB = 8;
export const pruneProtectedKinds = new Set<number>([0, 3, 10002]); // keep profile/contact/relay-list

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
