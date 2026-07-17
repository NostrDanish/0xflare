// 0xFlare PayGate - privacy-hardened Nostr payment relay (Nosflare fork)
// Stores zap events (NIP-57) + DMs. Pay-to-relay via Lightning (LNBits/LND).
// NIP-42 forced. No KYC, no account, no logging.

import {
  relayInfo, AUTH_REQUIRED, AUTH_TIMEOUT_MS, PAY_TO_RELAY_ENABLED,
  RELAY_ACCESS_PRICE_SATS, relayNpub,
  isPubkeyAllowed, isEventKindAllowed, containsBlockedContent, isTagAllowed,
  enableAntiSpam, enableGlobalDuplicateCheck, antiSpamKinds,
  PUBKEY_RATE_LIMIT, REQ_RATE_LIMIT, excludedRateLimitKinds,
  DB_PRUNING_ENABLED, DB_SIZE_THRESHOLD_GB, DB_PRUNE_BATCH_SIZE, DB_PRUNE_TARGET_GB,
  pruneProtectedKinds, blockedPubkeys, blockedEventKinds, blockedContent, blockedTags
} from './config';
import { NostrEvent, NostrFilter } from './types';
import { admitWithCashu, CashuProof } from './cashu';
import { ADMISSION_VIA_CASHU, ADMISSION_SATS } from './config';

import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

function eventId(ev: NostrEvent): string {
  const ser = JSON.stringify([0, ev.pubkey, ev.created_at, ev.kind, ev.tags, ev.content]);
  return bytesToHex(sha256(new TextEncoder().encode(ser)));
}
function verifySig(ev: NostrEvent): boolean {
  try {
    if (eventId(ev) !== ev.id) return false;
    return schnorr.verify(ev.sig, ev.id, ev.pubkey);
  } catch { return false; }
}

// Rate limiter
const buckets = new Map<string, { tokens: number; ts: number }>();
function rateOK(id: string, cfg: { rate: number; capacity: number }): boolean {
  const now = Date.now();
  let b = buckets.get(id);
  if (!b) { b = { tokens: cfg.capacity, ts: now }; buckets.set(id, b); }
  b.tokens = Math.min(cfg.capacity, b.tokens + (now - b.ts) * cfg.rate);
  b.ts = now;
  if (b.tokens >= 1) { b.tokens -= 1; return true; }
  return false;
}

// NIP-42 challenge
const challenges = new Map<string, number>();
function newChallenge(): string {
  const c = bytesToHex(sha256(new TextEncoder().encode(Math.random() + "" + Date.now())));
  challenges.set(c, Date.now());
  return c;
}

// --- Payment gate (LNBits/LND) ---
const paidPubkeys = new Set<string>(); // in-memory cache of admitted pubkeys
const cashuAdmitted = new Set<string>();
// Set LN backend endpoint via env: PAYMENT_URL, LN_API_KEY
async function checkPaid(env: any, pubkey: string): Promise<boolean> {
  if (paidPubkeys.has(pubkey)) return true;
  const url = env.PAYMENT_URL;
  if (!url) { console.warn('PAYMENT_URL unset - allowing (dev mode)'); return true; }
  try {
    const r = await fetch(`${url}/api/v1/paywall/check/${pubkey}`, {
      headers: { 'X-Api-Key': env.LN_API_KEY || '' }
    });
    if (r.ok) { paidPubkeys.add(pubkey); return true; }
  } catch (e) { console.error('LN check failed', e); }
  return false;
}

async function initDb(db: any) {
  await db.exec(`CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY, pubkey TEXT, created_at INTEGER, kind INTEGER, tags TEXT, content TEXT, sig TEXT
  );`);
  await db.exec(`CREATE INDEX IF NOT EXISTS idx_kind ON events(kind);`);
  await db.exec(`CREATE INDEX IF NOT EXISTS idx_pubkey ON events(pubkey);`);
  await db.exec(`CREATE TABLE IF NOT EXISTS seen_hashes (h TEXT PRIMARY KEY, kind INTEGER);`);
}
async function storeEvent(db: any, ev: NostrEvent) {
  await db.prepare(
    `INSERT OR IGNORE INTO events (id, pubkey, created_at, kind, tags, content, sig) VALUES (?,?,?,?,?,?,?)`
  ).bind(ev.id, ev.pubkey, ev.created_at, ev.kind, JSON.stringify(ev.tags), ev.content, ev.sig).run();
}
function matchFilter(ev: NostrEvent, f: NostrFilter): boolean {
  if (f.ids && !f.ids.includes(ev.id)) return false;
  if (f.authors && !f.authors.includes(ev.pubkey)) return false;
  if (f.kinds && !f.kinds.includes(ev.kind)) return false;
  if (f.since && ev.created_at < f.since) return false;
  if (f.until && ev.created_at > f.until) return false;
  return true;
}

export class RelayWebSocket {
  private env: any; private state: any;
  constructor(state: any, env: any) { this.env = env; this.state = state; }
  private sessions: WebSocket[] = [];

  async fetch(req: Request) {
    if (req.headers.get('Upgrade') !== 'websocket') return new Response('expected websocket', { status: 400 });
    const pair = new WebSocketPair();
    (this as any).acceptWebSocket(pair[1]);
    return new Response(null, { status: 101, webSocket: pair[0] });
  }
  async webSocketMessage(ws: WebSocket, msg: string | ArrayBuffer) {
    let data: any;
    try { data = JSON.parse(typeof msg === 'string' ? msg : new TextDecoder().decode(msg)); }
    catch { ws.send(JSON.stringify(['NOTICE', 'invalid json'])); return; }
    const t = data[0];
    if (t === 'EVENT') return this.handleEvent(ws, data[1]);
    if (t === 'REQ') return this.handleReq(ws, data[1], data.slice(2));
    if (t === 'AUTH') return this.handleAuth(ws, data[1]);
    if (t === 'CASHU') return this.handleCashu(ws, data[1]);
    if (t === 'CLOSE') return ws.close();
  }
  async webSocketClose() {}

  async handleAuth(ws: WebSocket, evt: any) {
    if (!AUTH_REQUIRED) return;
    if (!evt || evt.kind !== 22242) { ws.send(JSON.stringify(['NOTICE', 'auth requires kind 22242'])); return; }
    if (!verifySig(evt)) { ws.send(JSON.stringify(['NOTICE', 'bad auth sig'])); return; }
    const chal = evt.tags.find((t: string[]) => t[0] === 'challenge')?.[1];
    const ts = chal ? challenges.get(chal) : 0;
    if (!ts || Date.now() - ts > AUTH_TIMEOUT_MS) { ws.send(JSON.stringify(['NOTICE', 'challenge expired'])); return; }
    challenges.delete(chal);
    (ws as any)._authed = evt.pubkey;
    ws.send(JSON.stringify(['OK', evt.id, true, 'authenticated']));
  }

  async handleCashu(ws: WebSocket, msg: any) {
    if (AUTH_REQUIRED && !(ws as any)._authed) { ws.send(JSON.stringify(['NOTICE','auth first'])); return; }
    if (!ADMISSION_VIA_CASHU) { ws.send(JSON.stringify(['NOTICE','cashu disabled'])); return; }
    const proofs: CashuProof[] = msg.proofs || [];
    const err = await admitWithCashu((ws as any)._authed, proofs, cashuAdmitted);
    if (err) { ws.send(JSON.stringify(['NOTICE', 'cashu: ' + err])); return; }
    ws.send(JSON.stringify(['OK', 'cashu', true, 'admitted via ecash']));
  }
  async handleEvent(ws: WebSocket, ev: NostrEvent) {
    if (AUTH_REQUIRED && !(ws as any)._authed) {
      const chal = newChallenge();
      ws.send(JSON.stringify(['AUTH', chal]));
      ws.send(JSON.stringify(['OK', ev?.id || '', false, 'auth required']));
      return;
    }
    if (!ev || typeof ev !== 'object') { ws.send(JSON.stringify(['OK', '', false, 'invalid'])); return; }
    if (!isEventKindAllowed(ev.kind)) {
      ws.send(JSON.stringify(['OK', ev.id, false, 'kind not allowed on PayGate (use 4,1059,9734,9735)']));
      return;
    }
    if (!isPubkeyAllowed(ev.pubkey)) { ws.send(JSON.stringify(['OK', ev.id, false, 'pubkey blocked'])); return; }
    if (!verifySig(ev)) { ws.send(JSON.stringify(['OK', ev.id, false, 'bad sig'])); return; }
    // PAY-TO-RELAY GATE
    if (PAY_TO_RELAY_ENABLED) {
      if (ADMISSION_VIA_CASHU) {
        if (!cashuAdmitted.has(ev.pubkey)) {
          ws.send(JSON.stringify(['OK', ev.id, false, 'cashu admission required: send CASHU {proofs:[...]} for ' + ADMISSION_SATS + ' sats']));
          return;
        }
      } else {
        const paid = await checkPaid(this.env, ev.pubkey);
        if (!paid) {
          const payUrl = (this.env.PAYMENT_URL || '') + '/api/v1/paywall/' + ev.pubkey;
          ws.send(JSON.stringify(['OK', ev.id, false, 'payment required: ' + payUrl]));
          return;
        }
      }
    }
    if (enableAntiSpam && antiSpamKinds.has(ev.kind)) {
      const h = bytesToHex(sha256(new TextEncoder().encode(
        (enableGlobalDuplicateCheck ? '' : ev.pubkey) + ev.content)));
      const got = await this.env.RELAY_DATABASE.prepare('SELECT h FROM seen_hashes WHERE h=?').bind(h).first();
      if (got) { ws.send(JSON.stringify(['OK', ev.id, false, 'duplicate blocked'])); return; }
      await this.env.RELAY_DATABASE.prepare('INSERT OR IGNORE INTO seen_hashes (h,kind) VALUES (?,?)').bind(h, ev.kind).run();
    }
    await initDb(this.env.RELAY_DATABASE);
    await storeEvent(this.env.RELAY_DATABASE, ev);
    ws.send(JSON.stringify(['OK', ev.id, true, 'stored']));
    this.broadcast(ev);
  }

  async handleReq(ws: WebSocket, subId: string, filters: NostrFilter[]) {
    if (AUTH_REQUIRED && !(ws as any)._authed) {
      const chal = newChallenge();
      ws.send(JSON.stringify(['AUTH', chal]));
      return;
    }
    if (!rateOK((ws as any)._authed || 'anon', REQ_RATE_LIMIT)) { ws.send(JSON.stringify(['NOTICE', 'rate limited'])); return; }
    await initDb(this.env.RELAY_DATABASE);
    const evs = await this.env.RELAY_DATABASE.prepare(
      `SELECT id,pubkey,created_at,kind,tags,content,sig FROM events ORDER BY created_at DESC LIMIT 200`
    ).all();
    for (const row of (evs.results || [])) {
      const ev: NostrEvent = {
        id: row.id, pubkey: row.pubkey, created_at: row.created_at, kind: row.kind,
        tags: JSON.parse(row.tags), content: row.content, sig: row.sig
      };
      if (filters.some(f => matchFilter(ev, f))) ws.send(JSON.stringify(['EVENT', subId, ev]));
    }
    ws.send(JSON.stringify(['EOSE', subId]));
  }
  broadcast(ev: NostrEvent) {
    for (const ws of this.sessions) { try { ws.send(JSON.stringify(['EVENT', 'broadcast', ev])); } catch {} }
  }
}

export default {
  async fetch(req: Request, env: any, ctx: any) {
    if (req.headers.get('Upgrade') === 'websocket') {
      const ns = env.RELAY_WEBSOCKET;
      const id = ns.idFromName('0xflare-payment');
      return ns.get(id).fetch(req);
    }
    const url = new URL(req.url);
    if (url.pathname === '/') {
      const info = { ...relayInfo };
      if (PAY_TO_RELAY_ENABLED) {
        info.limitation = { ...info.limitation, payment_required: true, restricted_writes: true };
      }
      return new Response(JSON.stringify(info), {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }
      });
    }
    if (url.pathname === '/payments' && PAY_TO_RELAY_ENABLED) {
      return new Response(JSON.stringify({
        payments_url: url.origin + '/payments',
        fees: { admission: [{ amount: RELAY_ACCESS_PRICE_SATS * 1000, unit: 'msats' }] }
      }), { headers: { 'Content-Type': 'application/json' } });
    }
    return new Response('0xFlare PayGate - connect via Nostr client (wss)', { status: 200 });
  }
};
