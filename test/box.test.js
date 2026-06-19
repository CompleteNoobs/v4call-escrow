// ── v4call-escrow/test/box.test.js — the box proven IN ISOLATION ──────────────
// Drives the REAL escrow-box against the REAL escrow-core ledger/settle/disburse
// primitives, with only the two unavoidable externals injected: the chain reads
// (deps.getTransaction feeding the real verifyPayment) and the broadcast
// (deps.broadcastClient — a mock, so no key/funds/network). A throwaway, never-funded
// active key is generated purely so disburse()'s key path runs.
//
// What it proves (the money-safety claims the box rests on):
//   A  happy path settles + CONSERVES the envelope + the receipt verifies under the box key
//   B  a report from an UNAUTHORIZED reporter is rejected (hard gate #1)
//   C  a TAMPERED report fails the signature (hard gate #1)
//   D  an in-process REDELIVERY is a no-op (no double disburse)
//   E  a redelivery after RESTART (fresh box, same durable ledger) is a no-op (tx_id UNIQUE + atomicClose)
//   F  a LYING report can only RE-SPLIT the verified envelope — never mint/drain
//   G  a FORGED extra payment (not on chain) is dropped — can't inflate the envelope
//   H  a TRANSIENT verify error → retry (no close, no disburse), then the SAME report settles
//   I  no-key leaves refunds PENDING → disbursePending() recovers them EXACTLY once (crash/again path)

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const dhive = require('@hiveio/dhive');

const escrowCore = require('escrow-core');
const { createEscrowBox } = require('../escrow-box');

const NOW = 1_700_000_000_000;
const HALF_HOUR = 30 * 60 * 1000;
const KEY_ENV = 'TBOX_TEST_KEY';
// throwaway, never-funded — only so disburse()'s PrivateKey.fromString path runs.
const THROWAWAY_KEY = dhive.PrivateKey.fromSeed('v4call-escrow-box-test').toString();

function memo(purpose, callId) { return `v4call:${purpose}:${callId}`; }

// A mock chain: register real on-chain payments; unknown txIds resolve to an op-less tx
// (→ verifyPayment throws a STRUCTURAL unprocessable_entity, i.e. "forged/not found").
function makeChain() {
  const txs = new Map();
  return {
    add(txId, { sender, account, amount, currency = 'HBD', memo: m }) {
      txs.set(txId, { block_num: 100, operations: [
        ['transfer', { from: sender, to: account, amount: `${Number(amount).toFixed(3)} ${currency}`, memo: m }],
      ] });
    },
    getTransaction: async (txId) => txs.has(txId) ? txs.get(txId) : { block_num: null, operations: [] },
  };
}

function makeBroadcast() {
  const sent = [];
  let n = 0;
  return {
    sent,
    client: { broadcast: { sendOperations: async (ops) => {
      const id = 'mocktx_' + (++n);
      sent.push({ kind: ops[0][0], to: ops[0][1].to, amount: ops[0][1].amount, memo: ops[0][1].memo, id });
      return { id };
    } } },
  };
}

function setup({ now = NOW, reporters } = {}) {
  escrowCore.registerPrecision('HBD', 3);
  const adapter = escrowCore.createV4callAdapter({ account: 'tboxescrow', currency: 'HBD', keyEnv: KEY_ENV });
  const ledger = escrowCore.openLedger(':memory:', { adapterMigrations: adapter.ledgerMigrations() });
  const nodeSk = crypto.randomBytes(32).toString('hex');
  const nodePub = escrowCore.getReportingPubkey(nodeSk);
  const boxSk = crypto.randomBytes(32).toString('hex');
  const boxPub = escrowCore.getReportingPubkey(boxSk);
  const chain = makeChain();
  const broadcast = makeBroadcast();
  const config = { account: 'tboxescrow', currency: 'HBD', keyEnv: KEY_ENV, feeAccount: 'tplatform',
    expectedReporters: reporters || [nodePub], maxDurationMin: 120 };
  const mkBox = (extra = {}) => createEscrowBox({
    escrowCore, ledger, adapter, config, boxSkHex: boxSk,
    deps: { getTransaction: chain.getTransaction, broadcastClient: broadcast.client, now: () => now, ...extra },
    log: () => {},
  });
  return { adapter, ledger, nodeSk, nodePub, boxSk, boxPub, chain, broadcast, config, box: mkBox(), mkBox };
}

// Standard call: ring 0.01 → platform, connect 0.05 → callee, deposit 2.0 (refundable),
// 2/hr × 30min = 1.0 durationCost → 1.0 refund. fee 10%.
function standardCall(s, callId, { startTs = NOW - HALF_HOUR, ratePerHour = 2, sk } = {}) {
  const payments = [
    { txId: `tx_${callId}_ring`,    sender: 'caller', purpose: 'ring',    amount: 0.01, memo: memo('ring', callId) },
    { txId: `tx_${callId}_connect`, sender: 'caller', purpose: 'connect', amount: 0.05, memo: memo('connect', callId) },
    { txId: `tx_${callId}_dep`,     sender: 'caller', purpose: 'deposit', amount: 2.00, memo: memo('call', callId) },
  ];
  for (const p of payments) s.chain.add(p.txId, { sender: p.sender, account: s.config.account, amount: p.amount, memo: p.memo });
  const callFacts = { ratePerHour, platformFee: 0.10, callee: 'callee', startTs, maxDurationMin: 120 };
  const facts = { kind: 'call-end', endReason: 'hangup', endedAt: NOW, durationMs: HALF_HOUR, currency: 'HBD', callFacts,
    payments: payments.map(p => ({ txId: p.txId, sender: p.sender, purpose: p.purpose, amount: p.amount, memo: p.memo, currency: 'HBD' })) };
  const report = escrowCore.buildEventReport({ service: 'v4call', ref: callId, subject: callId, facts,
    nonce: `${callId}:settle`, createdAt: NOW, reporter: 'tnode' });
  return escrowCore.signReport(report, sk || s.nodeSk);
}

function sum(sent) { return sent.reduce((a, b) => a + parseFloat(b.amount), 0); }

test('A — happy path: settles, CONSERVES the envelope, receipt verifies', async () => {
  process.env[KEY_ENV] = THROWAWAY_KEY;
  const s = setup();
  const signed = standardCall(s, 'cA');
  const out = await s.box.handleReport(signed);

  assert.equal(out.status, 'settled');
  assert.equal(s.broadcast.sent.length, 3, 'payout + refund + fee disbursed');
  const byMemo = Object.fromEntries(s.broadcast.sent.map(x => [x.memo.split(':')[1], x]));
  assert.equal(parseFloat(byMemo.payout.amount), 0.945, 'callee net = (connect+durationCost) − 10%');
  assert.equal(parseFloat(byMemo.refund.amount), 1.0, 'caller refund = deposit − durationCost');
  assert.equal(parseFloat(byMemo.fee.amount), 0.115, 'platform = ring + 10% of gross');

  // CONSERVATION: out == ring + connect + deposit (2.06), never more.
  assert.ok(Math.abs(sum(s.broadcast.sent) - 2.06) < 1e-9, 'outflows conserve the verified envelope');

  // receipt is signed by the BOX key and verifies under the box pubkey
  assert.ok(escrowCore.verifyReport(out.receipt, s.boxPub), 'receipt verifies under box key');
  assert.equal(out.receipt.type, 'settlement-receipt');
  assert.equal(out.receipt.settlement, 1.0);
  assert.equal(out.receipt.refund, 1.0);

  // ledger terminal state
  const refunds = s.ledger.db.prepare('SELECT * FROM refunds WHERE ref = ?').all('cA');
  assert.equal(refunds.length, 3);
  assert.ok(refunds.every(r => r.status === 'sent' && r.tx_id), 'all refund rows sent with a tx_id');
  assert.ok(s.ledger.getPaymentsByRef('cA').every(p => p.settle_state === 'closed'), 'payments closed');
});

test('B — rejects a report from an UNAUTHORIZED reporter (hard gate)', async () => {
  process.env[KEY_ENV] = THROWAWAY_KEY;
  const s = setup();
  const attackerSk = crypto.randomBytes(32).toString('hex');
  const signed = standardCall(s, 'cB', { sk: attackerSk }); // validly signed, but by a key the box doesn't trust
  const out = await s.box.handleReport(signed);
  assert.equal(out.status, 'rejected');
  assert.equal(s.broadcast.sent.length, 0, 'nothing disbursed for an untrusted reporter');
});

test('C — rejects a TAMPERED report (signature fails)', async () => {
  process.env[KEY_ENV] = THROWAWAY_KEY;
  const s = setup();
  const signed = standardCall(s, 'cC');
  signed.facts.payments[2].amount = 999; // tamper the deposit after signing
  const out = await s.box.handleReport(signed);
  assert.equal(out.status, 'rejected');
  assert.equal(s.broadcast.sent.length, 0);
});

test('D — in-process REDELIVERY is a no-op (no double disburse)', async () => {
  process.env[KEY_ENV] = THROWAWAY_KEY;
  const s = setup();
  const signed = standardCall(s, 'cD');
  const first = await s.box.handleReport(signed);
  assert.equal(first.status, 'settled');
  assert.equal(s.broadcast.sent.length, 3);
  const again = await s.box.handleReport(signed);     // exact redelivery
  assert.equal(again.status, 'duplicate');
  assert.equal(s.broadcast.sent.length, 3, 'still exactly 3 disbursements');
});

test('E — redelivery after RESTART (fresh box, same durable ledger) is a no-op', async () => {
  process.env[KEY_ENV] = THROWAWAY_KEY;
  const s = setup();
  const signed = standardCall(s, 'cE');
  await s.box.handleReport(signed);
  assert.equal(s.broadcast.sent.length, 3);

  const box2 = s.mkBox();                              // new instance → fresh seenIds; SAME ledger
  const out = await box2.handleReport(signed);         // durable guards must catch it
  assert.equal(out.status, 'already_settled');
  assert.equal(s.broadcast.sent.length, 3, 'durable tx_id UNIQUE + atomicClose prevent re-settle');
  assert.ok(escrowCore.verifyReport(out.receipt, s.boxPub), 'returns a valid prior receipt');
});

test('F — a LYING report can only RE-SPLIT the verified envelope, never mint/drain', async () => {
  process.env[KEY_ENV] = THROWAWAY_KEY;
  const s = setup();
  // node lies: rate 1000/hr (vs the honest 2) → usage huge → durationCost capped at deposit.
  const signed = standardCall(s, 'cF', { ratePerHour: 1000 });
  const out = await s.box.handleReport(signed);
  assert.equal(out.status, 'settled');

  const byMemo = Object.fromEntries(s.broadcast.sent.map(x => [x.memo.split(':')[1], x]));
  assert.equal(out.receipt.settlement, 2.0, 'durationCost capped at the verified deposit');
  assert.equal(out.receipt.refund, 0, 'caller refund squeezed to 0 (the re-split harm)');
  // …but the TOTAL out is still exactly the verified envelope — no mint, no drain.
  assert.ok(Math.abs(sum(s.broadcast.sent) - 2.06) < 1e-9, 'total out == ring+connect+deposit');
  assert.ok(!byMemo.refund, 'no refund outflow when refund rounds to 0');
});

test('G — a FORGED extra payment (not on chain) is dropped, envelope unchanged', async () => {
  process.env[KEY_ENV] = THROWAWAY_KEY;
  const s = setup();
  const callId = 'cG';
  // honest payments + one forged deposit txId that was never broadcast on-chain
  const honest = [
    { txId: `tx_${callId}_dep`, sender: 'caller', purpose: 'deposit', amount: 2.00, memo: memo('call', callId) },
  ];
  for (const p of honest) s.chain.add(p.txId, { sender: p.sender, account: s.config.account, amount: p.amount, memo: p.memo });
  const all = honest.concat([{ txId: 'tx_FORGED', sender: 'caller', purpose: 'deposit', amount: 1000, memo: memo('call', callId) }]);
  const callFacts = { ratePerHour: 2, platformFee: 0.10, callee: 'callee', startTs: NOW - HALF_HOUR, maxDurationMin: 120 };
  const facts = { kind: 'call-end', endReason: 'hangup', endedAt: NOW, durationMs: HALF_HOUR, currency: 'HBD', callFacts,
    payments: all.map(p => ({ txId: p.txId, sender: p.sender, purpose: p.purpose, amount: p.amount, memo: p.memo, currency: 'HBD' })) };
  const report = escrowCore.buildEventReport({ service: 'v4call', ref: callId, subject: callId, facts, nonce: `${callId}:settle`, createdAt: NOW, reporter: 'tnode' });
  const signed = escrowCore.signReport(report, s.nodeSk);

  const out = await s.box.handleReport(signed);
  assert.equal(out.status, 'settled');
  // only the real 2.0 deposit counts: durationCost 1.0 → refund 1.0; no connect/ring here.
  assert.ok(Math.abs(sum(s.broadcast.sent) - 2.0) < 1e-9, 'forged 1000 dropped — envelope is the real 2.0');
  assert.equal(s.ledger.getPaymentsByRef(callId).length, 1, 'only the verified payment recorded');
});

test('H — a TRANSIENT verify error → retry (no close/disburse), then the SAME report settles', async () => {
  process.env[KEY_ENV] = THROWAWAY_KEY;
  let blowUp = true;
  const s = setup();
  // wrap getTransaction to throw a network-like error (no code) on the first pass
  const realGet = s.chain.getTransaction;
  const flaky = async (txId) => { if (blowUp) throw new Error('All Hive nodes failed'); return realGet(txId); };
  const box = s.mkBox({ getTransaction: flaky });

  const signed = standardCall(s, 'cH');
  const retry = await box.handleReport(signed);
  assert.equal(retry.status, 'retry', 'transient error → retry');
  assert.equal(s.broadcast.sent.length, 0, 'nothing disbursed on a transient failure');
  assert.equal(s.ledger.getPaymentsByRef('cH').length, 0, 'no rows recorded, nothing closed');

  blowUp = false;                                       // chain recovers
  const ok = await box.handleReport(signed);            // SAME stable nonce must NOT be blocked
  assert.equal(ok.status, 'settled', 'retry of the same report settles (nonce not wrongly consumed)');
  assert.equal(s.broadcast.sent.length, 3);
});

test('J — round-trip over a transport: start() wires subscribe→handle→publish; node verifies receipt', async () => {
  process.env[KEY_ENV] = THROWAWAY_KEY;
  const s = setup();
  let handler = null;
  const published = [];
  const transport = {
    subscribe(cb) { handler = cb; },
    async publish(receipt, opts) { published.push({ receipt, opts }); },
  };
  const box = s.mkBox({ transport });
  await box.start();                                    // wires subscribe + recovers any pending
  assert.equal(typeof handler, 'function', 'box subscribed for event-reports');

  const signed = standardCall(s, 'cJ');
  await handler(signed);                                // simulate an inbound report (node → box)

  assert.equal(s.broadcast.sent.length, 3, 'box settled on the inbound report');
  assert.equal(published.length, 1, 'box published a settlement-receipt back');
  assert.equal(published[0].opts.to, s.nodePub, 'receipt addressed to the reporting node');
  assert.ok(escrowCore.verifyReport(published[0].receipt, s.boxPub), 'node verifies the receipt under the box key');
  assert.equal(published[0].receipt.ref, 'cJ');
});

test('K — end-to-end: node builds the envelope from its durable rows → box settles + conserves', async () => {
  process.env[KEY_ENV] = THROWAWAY_KEY;
  const s = setup();
  const callId = 'cK';

  // NODE side: its own ledger holding the call's verified+recorded payments (pay-time state).
  const nodeAdapter = escrowCore.createV4callAdapter({ account: s.config.account, currency: 'HBD', keyEnv: KEY_ENV });
  const nodeLedger = escrowCore.openLedger(':memory:', { adapterMigrations: nodeAdapter.ledgerMigrations() });
  const pays = [
    { tx: `tx_${callId}_ring`,    purpose: 'ring',    onchainMemo: memo('ring', callId),    amount: 0.01 },
    { tx: `tx_${callId}_connect`, purpose: 'connect', onchainMemo: memo('connect', callId), amount: 0.05 },
    { tx: `tx_${callId}_dep`,     purpose: 'deposit', onchainMemo: memo('call', callId),    amount: 2.00 },
  ];
  for (const p of pays) {
    s.chain.add(p.tx, { sender: 'caller', account: s.config.account, amount: p.amount, memo: p.onchainMemo }); // on-chain — box re-verifies
    const row = { tx_id: p.tx, ref: callId, sender: 'caller', currency: 'HBD', amount: p.amount, memo: p.onchainMemo };
    if (p.purpose === 'deposit') { row.rate_per_hour = 2; row.start_ts = NOW - HALF_HOUR; row.platform_fee = 0.10; row.callee = 'callee'; }
    nodeLedger.recordPayment(row);
  }

  // NODE (keyless) builds the report from its durable rows — the exact path the flip will use.
  const facts = nodeAdapter.buildCallEndReportFacts({ payRows: nodeLedger.getPaymentsByRef(callId), endReason: 'hangup', now: NOW, maxDurationMin: 120 });
  assert.equal(facts.payments.length, 3);
  assert.equal(facts.callFacts.callee, 'callee');
  const report = escrowCore.buildEventReport({ service: 'v4call', ref: callId, subject: callId, facts, nonce: `${callId}:settle`, createdAt: NOW, reporter: 'tnode' });
  const signed = escrowCore.signReport(report, s.nodeSk);

  // BOX re-verifies each tx on-chain and settles.
  const out = await s.box.handleReport(signed);
  assert.equal(out.status, 'settled');
  assert.ok(Math.abs(sum(s.broadcast.sent) - 2.06) < 1e-9, 'box settled the node-built envelope, conserved');
  assert.ok(escrowCore.verifyReport(out.receipt, s.boxPub), 'node can verify the box receipt');
  nodeLedger.close();
});

test('I — no-key leaves refunds PENDING → disbursePending() recovers EXACTLY once', async () => {
  const s = setup();
  delete process.env[KEY_ENV];                          // box has no active key
  const signed = standardCall(s, 'cI');
  const out = await s.box.handleReport(signed);
  assert.equal(out.status, 'pending', 'no key → settlement pending');
  assert.equal(s.broadcast.sent.length, 0, 'nothing broadcast without a key');
  const pending = s.ledger.db.prepare("SELECT * FROM refunds WHERE ref='cI' AND status='pending'").all();
  assert.equal(pending.length, 3, 'three pending refund rows survive');

  // operator provisions the key on the box; recovery disburses the pending rows once.
  process.env[KEY_ENV] = THROWAWAY_KEY;
  const n1 = await s.box.disbursePending();
  assert.equal(n1, 3, 'recovered 3 pending refunds');
  assert.equal(s.broadcast.sent.length, 3);
  const n2 = await s.box.disbursePending();             // re-run = no-op
  assert.equal(n2, 0, 'second recovery disburses nothing more (exactly once)');
  assert.equal(s.broadcast.sent.length, 3);
  delete process.env[KEY_ENV];
});

// ── Combined-transfer re-split (Option B) ─────────────────────────────────────
// The LIVE node funds ring+connect+deposit as ONE on-chain transfer (memo v4call:call) and
// records it as a SINGLE deposit-purpose row, asserting the non-refundable ring/connect
// portions as callFacts. The box re-splits them out of the verified deposit envelope. The node
// REPORTS only the refundable cap as the payment amount (2.00); the box independently reads the
// real on-chain total (2.06) and settles against that — proving the box is the authority.
function combinedCall(s, callId, { startTs = NOW - HALF_HOUR, ratePerHour = 2,
  ringPaid = 0.01, connectPaid = 0.05, onchainTotal = 2.06, depositReported = 2.00, sk } = {}) {
  const txId = `tx_${callId}_combined`;
  const m = memo('call', callId);
  s.chain.add(txId, { sender: 'caller', account: s.config.account, amount: onchainTotal, memo: m });
  const callFacts = { ratePerHour, platformFee: 0.10, callee: 'callee', startTs, maxDurationMin: 120, connectPaid, ringPaid };
  const facts = { kind: 'call-end', endReason: 'hangup', endedAt: NOW, durationMs: HALF_HOUR, currency: 'HBD', callFacts,
    payments: [{ txId, sender: 'caller', purpose: 'deposit', amount: depositReported, memo: m, currency: 'HBD' }] };
  const report = escrowCore.buildEventReport({ service: 'v4call', ref: callId, subject: callId, facts,
    nonce: `${callId}:settle`, createdAt: NOW, reporter: 'tnode' });
  return escrowCore.signReport(report, sk || s.nodeSk);
}

test('L — combined transfer: box re-splits asserted ring/connect, conserves, IDENTICAL to separate-transfer', async () => {
  process.env[KEY_ENV] = THROWAWAY_KEY;
  const s = setup();
  const signed = combinedCall(s, 'cL');
  const out = await s.box.handleReport(signed);

  assert.equal(out.status, 'settled');
  assert.equal(s.broadcast.sent.length, 3, 'payout + refund + fee');
  const byMemo = Object.fromEntries(s.broadcast.sent.map(x => [x.memo.split(':')[1], x]));
  // EXACTLY the numbers test A produced from three separate transfers — the re-split is faithful.
  assert.equal(parseFloat(byMemo.payout.amount), 0.945, 'callee net = (connect+durationCost) − 10%');
  assert.equal(parseFloat(byMemo.refund.amount), 1.0, 'caller refund = deposit − durationCost');
  assert.equal(parseFloat(byMemo.fee.amount), 0.115, 'platform = ring + 10% of gross (ring carved back from deposit)');
  // CONSERVATION: the box settled the REAL on-chain total (2.06), not the reported cap (2.00).
  assert.ok(Math.abs(sum(s.broadcast.sent) - 2.06) < 1e-9, 'conserves the on-chain-verified envelope');
  assert.ok(escrowCore.verifyReport(out.receipt, s.boxPub), 'receipt verifies under box key');
  assert.equal(out.receipt.settlement, 1.0);
  assert.equal(out.receipt.refund, 1.0);
});

test('M — a LYING combined re-split (inflated connect, still ≤ deposit) can only RE-SPLIT, never mint', async () => {
  process.env[KEY_ENV] = THROWAWAY_KEY;
  const s = setup();
  // node lies: claims almost the whole 2.06 transfer was non-refundable connect (→ callee).
  // That's a re-split harm (caller refund squeezed), but the TOTAL out is still the verified 2.06.
  const signed = combinedCall(s, 'cM', { connectPaid: 2.00, ringPaid: 0.01 });
  const out = await s.box.handleReport(signed);
  assert.equal(out.status, 'settled');
  assert.ok(Math.abs(sum(s.broadcast.sent) - 2.06) < 1e-9, 'total out == verified envelope — no mint, no drain');
  // deposit bucket squeezed to 0.05 → caller refund collapses; callee gets the lion's share.
  assert.ok(out.receipt.refund < 0.06, 'refund squeezed by the inflated connect claim (the re-split harm)');
});

test('N — an OVER-ASSERTED re-split (ring+connect > verified deposit) is rejected BEFORE any close', async () => {
  process.env[KEY_ENV] = THROWAWAY_KEY;
  const s = setup();
  // assert more non-refundable than the whole transfer holds — can't re-split money that isn't there.
  const signed = combinedCall(s, 'cN', { connectPaid: 3.00, ringPaid: 0.01 });
  const out = await s.box.handleReport(signed);
  assert.equal(out.status, 'rejected');
  assert.equal(out.reason, 'asserted_split_exceeds_deposit');
  assert.equal(s.broadcast.sent.length, 0, 'nothing disbursed');
  // rejected pre-commit → the ref is NOT closed; a corrected re-report can still settle it.
  assert.equal(s.ledger.getPaymentsByRef('cN').length, 0, 'no rows recorded, ref left open for a corrected re-report');
});
