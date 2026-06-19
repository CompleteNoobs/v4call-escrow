// ── v4call-escrow/nostr-transport.mjs — escrow-protocol/0.1 over Nostr (via nGate) ──
//
// The SWAPPABLE transport seam (handover-escrow-core §4): escrow-protocol payloads are
// schnorr-signed over a CANONICAL payload by escrow-core (signReport/verifyReport), so the
// transport is just an envelope. Here that envelope is a Nostr event carried over the same
// relays the node already federates on (nGate). The box subscribes for event-reports
// addressed to its pubkey and publishes settlement-receipts back to the reporting node.
//
// SECURITY NOTE: the trust gate is the INNER escrow-protocol signature (escrowCore.verifyReport
// against the node's on-chain-bound reporting key), checked in escrow-box.js — NOT the Nostr
// event signature. The Nostr layer is only delivery + relay-level dedup. A relay cannot forge
// a report it can't inner-sign, and a replayed event is dropped by the event-id seenIds here
// plus the durable tx_id/atomicClose guards in the box.
//
// DEPLOY-TIME: this module talks to live relays, so it is exercised at deployment, not in the
// offline test suite (which drives escrow-box.handleReport directly over a loopback transport).
//
// Requires nostr-tools v2 (ESM). Loaded from index.js via dynamic import.

import { SimplePool } from 'nostr-tools/pool';
import { finalizeEvent, verifyEvent } from 'nostr-tools/pure';

// Dedicated kind for escrow-protocol/0.1 envelopes (regular, relayed events). Distinct from
// the federation kinds (1314 fedmsg / 30078 discovery) so relays/filters never cross them.
const ESCROW_KIND = 31337;
const TAG_TOPIC = 'escrow-protocol';

function hexToBytes(hex) {
  const clean = String(hex || '').trim();
  const a = new Uint8Array(clean.length / 2);
  for (let i = 0; i < a.length; i++) a[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return a;
}

/**
 * Create a Nostr transport for one escrow endpoint.
 *
 * @param relays      string[] of wss:// relay URLs (the nGate relays)
 * @param selfSkHex   64-hex schnorr secret key used to SIGN the Nostr events this side publishes
 *                    (for the box: the same key it signs receipts with — its escrow-reporting key)
 * @param now         () => epoch ms  (created_at source; injected so the box stays clock-pure)
 * @param log         (level, msg) => void
 *
 * Returns { subscribe(onPayload), publish(payload, { to }), close() }:
 *   - subscribe(onPayload): onPayload(parsedEscrowPayload) for each inbound escrow event tagged
 *     to selfPubkey. (The box hands this straight to handleReport, which does the real verify.)
 *   - publish(payload, { to }): wrap the signed escrow payload in a kind-31337 event tagged
 *     ['p', to] and broadcast it to all relays.
 */
export function createNostrTransport({ relays, selfSkHex, now = () => Date.now(), log = () => {} }) {
  if (!Array.isArray(relays) || relays.length === 0) throw new Error('nostr-transport: relays[] required');
  if (!/^[0-9a-f]{64}$/i.test(String(selfSkHex || ''))) throw new Error('nostr-transport: selfSkHex must be 64-hex');
  const skBytes = hexToBytes(selfSkHex);
  const selfPub = finalizeEvent({ kind: ESCROW_KIND, content: '', tags: [], created_at: 0 }, skBytes).pubkey;
  const pool = new SimplePool();
  const seenEventIds = new Set();
  let sub = null;

  function subscribe(onPayload) {
    // NB: subscribeMany takes a SINGLE filter object (it wraps it internally). Passing an
    // array double-wraps it → strict relays (strfry) reject "filter is not an object".
    sub = pool.subscribeMany(relays, { kinds: [ESCROW_KIND], '#p': [selfPub] }, {
      onevent: (ev) => {
        try {
          if (seenEventIds.has(ev.id)) return;          // relay-level one-shot
          seenEventIds.add(ev.id);
          if (seenEventIds.size > 5000) seenEventIds.clear();
          if (!verifyEvent(ev)) return;                 // malformed event — drop (inner sig is the real gate)
          const payload = JSON.parse(ev.content);
          Promise.resolve(onPayload(payload)).catch(e => log('error', `onPayload threw: ${e.message}`));
        } catch (e) { log('warn', `bad escrow event ${ev && ev.id}: ${e.message}`); }
      },
    });
    log('info', `subscribed for escrow events on ${relays.length} relay(s) as ${selfPub.slice(0, 12)}…`);
  }

  async function publish(payload, { to } = {}) {
    const tags = [['t', TAG_TOPIC]];
    if (to) tags.push(['p', to]);
    const ev = finalizeEvent(
      { kind: ESCROW_KIND, content: JSON.stringify(payload), tags, created_at: Math.floor(now() / 1000) },
      skBytes
    );
    const results = await Promise.allSettled(pool.publish(relays, ev));
    const ok = results.filter(r => r.status === 'fulfilled').length;
    log('info', `published ${payload.type} for ${payload.ref} → ${ok}/${relays.length} relay(s)`);
    return { id: ev.id, accepted: ok };
  }

  function close() { try { if (sub) sub.close(); } catch {} try { pool.close(relays); } catch {} }

  return { subscribe, publish, close, selfPub, ESCROW_KIND };
}
