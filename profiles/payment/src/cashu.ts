// Cashu admission for 0xFlare PayGate (no LN correlation = most private)
// Clients present ecash proofs (NUT-00) minted at MINT_URL. Relay swaps them
// with the mint, then admits the pubkey. No account, no IP-linked payment log.

import { MINT_URL, ADMISSION_SATS } from './config';

export interface CashuProof {
  id: string;
  amount: number;
  secret: string;
  C: string;
}

// Verify the client-sent proofs are well-formed and sum to required amount.
export function validateProofs(proofs: CashuProof[]): number {
  let total = 0;
  for (const p of proofs) {
    if (!p.id || !p.secret || !p.C || typeof p.amount !== 'number') {
      throw new Error('malformed proof');
    }
    total += p.amount;
  }
  return total;
}

// Swap proofs with mint: POST /v1/swap to burn them (prevents double-spend).
// Returns true if mint accepted (proofs valid + sufficient value).
export async function redeemAtMint(proofs: CashuProof[]): Promise<boolean> {
  try {
    const res = await fetch(`${MINT_URL}/v1/swap`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ inputs: proofs, outputs: [] })
    });
    // 200 = proofs burned successfully by mint
    return res.ok;
  } catch (e) {
    console.error('mint swap failed', e);
    return false;
  }
}

// Admission flow: client sends { proofs } after NIP-42 auth.
// If total >= ADMISSION_SATS and mint burns them, pubkey is admitted.
export async function admitWithCashu(pubkey: string, proofs: CashuProof[], cache: Set<string>): Promise<string | null> {
  if (cache.has(pubkey)) return null;
  let total: number;
  try { total = validateProofs(proofs); }
  catch { return 'invalid ecash'; }
  if (total < ADMISSION_SATS) return `need ${ADMISSION_SATS} sats, got ${total}`;
  const ok = await redeemAtMint(proofs);
  if (!ok) return 'mint rejected ecash';
  cache.add(pubkey);
  return null; // admitted
}
