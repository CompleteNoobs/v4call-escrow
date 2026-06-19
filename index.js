// ── v4call-escrow/index.js — the money-box boot entrypoint ────────────────────
//
// Runs the isolated v4call escrow box (the SETTLEMENT AUTHORITY). On its own minimal
// Alpine host this is the ONLY process that holds the active key (V4CALL_ESCROW_KEY) and
// the only place a disbursement is computed and signed. It opens its OWN durable ledger,
// trusts reports only from the node reporting-key(s) in ESCROW_EXPECTED_REPORTERS, and
// settles each call's verified on-chain envelope (see escrow-box.js for the safety proof).
//
// GUARDRAIL: no Claude / no dev tooling on this host. Operate via logs + `docker exec`.

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const escrowCore = require('escrow-core');
const { createEscrowBox } = require('./escrow-box');

function reqEnv(name) {
  const v = (process.env[name] || '').trim();
  if (!v) { console.error(`[escrow-box] FATAL: ${name} is required`); process.exit(1); }
  return v;
}

// The box's escrow-reporting key (schnorr): signs settlement-receipts AND the Nostr events
// it publishes. Persisted so its pubkey is stable (the node pins it to verify receipts).
function loadOrCreateBoxKey(keyPath) {
  try {
    const j = JSON.parse(fs.readFileSync(keyPath, 'utf8'));
    if (/^[0-9a-f]{64}$/i.test(j.sk_hex || '')) return j.sk_hex.toLowerCase();
    throw new Error('sk_hex missing/invalid');
  } catch (e) {
    if (e.code !== 'ENOENT') console.warn(`[escrow-box] ${keyPath}: ${e.message} — generating a fresh key`);
    const skHex = crypto.randomBytes(32).toString('hex');
    const pubkey = escrowCore.getReportingPubkey(skHex);
    fs.mkdirSync(path.dirname(keyPath), { recursive: true });
    fs.writeFileSync(keyPath, JSON.stringify({ sk_hex: skHex, pubkey, created_at: new Date().toISOString() }, null, 2), { mode: 0o600 });
    console.log(`[escrow-box] generated box reporting key → ${keyPath} (pubkey ${pubkey})`);
    return skHex;
  }
}

async function main() {
  const account  = process.env.ESCROW_ACCOUNT || 'v4call-escrow';
  const currency = (process.env.ESCROW_CURRENCY || 'HBD').toUpperCase();
  const keyEnv   = 'V4CALL_ESCROW_KEY';
  reqEnv(keyEnv);                                  // the active key MUST be present on the box
  const feeAccount = reqEnv('FEE_ACCOUNT');
  const dbPath   = process.env.ESCROW_DB_PATH || path.join(__dirname, 'data', 'v4call-escrow.db');
  const keyPath  = process.env.ESCROW_KEY_PATH || path.join(__dirname, 'data', 'escrow-reporting-key.json');
  const relays   = (process.env.NOSTR_RELAYS || '').split(',').map(s => s.trim()).filter(Boolean);
  const reporters = (process.env.ESCROW_EXPECTED_REPORTERS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
  const maxDurationMin = parseInt(process.env.MAX_CALL_DURATION_MIN || '120', 10);

  if (reporters.length === 0) { console.error('[escrow-box] FATAL: ESCROW_EXPECTED_REPORTERS is required (fail-closed: a money box must know which node key(s) it trusts)'); process.exit(1); }
  if (!reporters.every(r => /^[0-9a-f]{64}$/.test(r))) { console.error('[escrow-box] FATAL: ESCROW_EXPECTED_REPORTERS must be 64-hex schnorr pubkeys'); process.exit(1); }

  // Non-native token precision must be locked explicitly (Decision #3).
  if (currency !== 'HBD' && currency !== 'HIVE') {
    const p = parseInt(process.env.ESCROW_TOKEN_PRECISION || '', 10);
    if (!Number.isInteger(p)) { console.error(`[escrow-box] FATAL: ESCROW_TOKEN_PRECISION required for non-native currency ${currency}`); process.exit(1); }
    escrowCore.registerPrecision(currency, p);
  }

  const boxSkHex = loadOrCreateBoxKey(keyPath);
  const boxPub   = escrowCore.getReportingPubkey(boxSkHex);
  const adapter  = escrowCore.createV4callAdapter({ account, currency, keyEnv });
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const ledger   = escrowCore.openLedger(dbPath, { adapterMigrations: adapter.ledgerMigrations() });

  const { createNostrTransport } = await import('./nostr-transport.mjs');
  const log = (lvl, msg) => console[lvl === 'error' ? 'error' : 'log'](`[escrow-box] ${msg}`);
  const transport = relays.length
    ? createNostrTransport({ relays, selfSkHex: boxSkHex, log })
    : null;
  if (!transport) console.warn('[escrow-box] NOSTR_RELAYS empty — running WITHOUT a transport (recovery-only/diagnostic mode)');

  const box = createEscrowBox({
    escrowCore, ledger, adapter,
    config: { account, currency, keyEnv, feeAccount, expectedReporters: reporters, maxDurationMin },
    boxSkHex,
    deps: { transport },          // getTransaction/broadcastClient default to LIVE chain
    log,
  });

  await box.start();
  console.log(`[escrow-box] escrow-core ${escrowCore.version} ready: @${account} (${currency}) · ledger ${dbPath}`);
  console.log(`[escrow-box]   box reporting pubkey: ${boxPub}   ← the node must pin this to verify receipts`);
  console.log(`[escrow-box]   trusts ${reporters.length} reporter key(s); fee → @${feeAccount}; ${relays.length} relay(s)`);

  const shutdown = () => { try { if (transport) transport.close(); ledger.close(); } catch {} process.exit(0); };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch(e => { console.error('[escrow-box] FATAL:', e); process.exit(1); });
