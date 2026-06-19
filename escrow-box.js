// ── v4call-escrow/escrow-box.js — the isolated money box (the SETTLEMENT AUTHORITY) ──
//
// This is the thin wrapper around escrow-core that makes the box — NOT the node — the
// money authority (handover-escrow-core §4/§9.1; decoupling handoff item 1). The box
// holds the ONLY active key, its OWN durable ledger, and is the only place a
// disbursement is computed and signed. The node becomes a keyless reporter: it sends a
// signed `event-report` describing a call that ended; the box independently re-establishes
// the money facts ON-CHAIN and settles.
//
// THE SAFETY PROPERTY (why a compromised node can't drain funds):
//   The box verifies EVERY escrowed payment (ring/connect/deposit/topup) on-chain itself
//   (escrow-core.verifyPayment, tx-anchored + exact-memo) and only ever disburses within
//   that verified envelope. The split (adapter.settlementSplit) conserves the envelope:
//       payout + refund + fee  ==  ring + connect + deposit − dust   (for ANY rate/fee/duration)
//   So a lying report can only RE-SPLIT a call's verified deposit between caller/callee/
//   platform — never mint money, never exceed what was actually escrowed for that call.
//   The report's signature gate (verifyReport against the node's on-chain-bound reporting
//   key) + the nonce one-shot stop spoofed/replayed *settlements*; the on-chain verify +
//   the conservation are what stop *minting*.
//
// IDEMPOTENCY (no double-disburse, ever): two durable guards, exactly as in-process today.
//   - tx_id UNIQUE  → a replayed payment can't be recorded (or counted) twice.
//   - atomicClose() → a single-winner state flip; a redelivered report / crash-retry / two
//     concurrent reports for the same ref produce exactly ONE settlement.
//
// PURE + INJECTABLE (so it is provable offline): all I/O is injected — `transport`
// (subscribe/publish), `deps.getTransaction` (chain reads for verifyPayment),
// `deps.broadcastClient` (the dhive client for disburse), `deps.verifySidechain`,
// `deps.now`. The real Nostr transport + real chain live in index.js / nostr-transport.js;
// the tests drive handleReport() directly with a loopback transport and a mock chain.
//
// NO CLAUDE ON THE MONEY BOX (guardrail): this file is developed/tested on a dev host; the
// production box runs it on a minimal Alpine host with no dev tooling.

'use strict';

// Purposes whose on-chain amount forms the refundable DEPOSIT cap (vs the non-refundable
// ring → platform and connect → callee buckets). Classification is by the on-chain-verified
// memo purpose (`namespace:purpose:reservationId`), so it can't be spoofed by the node.
const DEPOSIT_PURPOSES = new Set(['call', 'deposit', 'topup']);

function isTransient(err) {
  // escrow-core.verifyPayment throws CODED errors for every on-chain verdict:
  //   'bad_request'          → missing/invalid params (structural)
  //   'unprocessable_entity' → the tx doesn't prove the payment (wrong account/currency/
  //                            amount/memo, no matching op, or — after verifyPayment's own
  //                            5× confirmation-lag retries — not found). All structural.
  // Anything WITHOUT one of those codes is a thrown network/timeout (e.g. "All Hive nodes
  // failed") → transient. We must NOT finalize a settlement on incomplete data: a transient
  // error returns 'retry' (the node re-reports) BEFORE atomicClose, so nothing is lost; a
  // structural error DROPS that one payment (a forged/wrong tx can't enter the envelope).
  if (!err) return false;
  return err.code !== 'bad_request' && err.code !== 'unprocessable_entity';
}

/**
 * Create an escrow box bound to one escrow account/key/ledger.
 *
 * @param escrowCore  require('escrow-core')
 * @param ledger      escrowCore.openLedger(dbPath, { adapterMigrations: adapter.ledgerMigrations() })
 * @param adapter     escrowCore.createV4callAdapter({ account, currency, keyEnv })
 * @param config      { account, currency, keyEnv, feeAccount, expectedReporters:[pubkeyHex…], maxDurationMin? }
 * @param boxSkHex    64-hex schnorr sk for SIGNING settlement-receipts (the box's escrow-reporting key)
 * @param deps        { getTransaction, broadcastClient, verifySidechain?, now? }  (injected; defaults = live)
 * @param log         (level, msg) => void
 */
function createEscrowBox({ escrowCore, ledger, adapter, config, boxSkHex, deps = {}, log = () => {} }) {
  if (!escrowCore || !ledger || !adapter || !config) throw new Error('createEscrowBox: escrowCore, ledger, adapter, config are required');
  if (!config.account || !config.keyEnv) throw new Error('createEscrowBox: config.account + config.keyEnv are required');

  const seen = escrowCore.createSeenIds();
  const nowFn = () => (deps.now ? deps.now() : Date.now());
  const expectedReporters = new Set(config.expectedReporters || []);

  const reject = (ref, reason) => { log('warn', `report rejected (ref=${ref}): ${reason}`); return { status: 'rejected', ref, reason }; };

  function authorizedReporter(pubkey) {
    // If no allow-list is configured the box refuses ALL reports (fail closed) — a money
    // box must know which reporting key(s) it trusts.
    return !!pubkey && expectedReporters.has(pubkey);
  }

  function placesFor(currency) {
    return adapter.precision(currency || config.currency);
  }

  // Build a settlement-receipt from the durable state of an already-settled ref, so a
  // redelivered report gets the SAME answer without re-disbursing.
  function receiptFromLedger(ref, status) {
    const refunds = ledger.db.prepare('SELECT * FROM refunds WHERE ref = ?').all(ref);
    const byReason = (r) => refunds.filter(x => x.reason === r).reduce((s, x) => s + Number(x.amount || 0), 0);
    const payout = refunds.find(r => r.reason === 'payout');
    const currency = refunds[0] ? refunds[0].currency : config.currency;
    const receipt = escrowCore.buildSettlementReceipt({
      ref, settlement: byReason('payout'), refund: byReason('refund'),
      dust: 0, currency, disburseTx: (payout && payout.tx_id) || null,
      status: status || 'settled', createdAt: nowFn(),
    });
    return boxSkHex ? escrowCore.signReport(receipt, boxSkHex) : receipt;
  }

  /**
   * Handle one signed event-report. Returns one of:
   *   { status:'settled'|'pending'|'failed', ref, receipt, outflows }   — a real settlement
   *   { status:'duplicate'|'already_settled', ref, receipt? }           — idempotent no-op
   *   { status:'retry', ref, reason }                                   — transient; node re-reports
   *   { status:'rejected', ref, reason }                                — bad sig / unauthorized / shape
   */
  async function handleReport(signed) {
    const ref = signed && signed.ref;

    // 1. shape / proto / type
    if (!signed || signed.proto !== escrowCore.PROTO || signed.type !== 'event-report') return reject(ref, 'bad_shape');
    if (!ref || !signed.nonce) return reject(ref, 'missing ref/nonce');

    // 2. HARD GATE — authorized reporter + valid schnorr signature over the canonical payload
    if (!authorizedReporter(signed.pubkey)) return reject(ref, `unauthorized reporter pubkey ${signed.pubkey}`);
    if (!escrowCore.verifyReport(signed, signed.pubkey)) return reject(ref, 'bad signature');

    // 3. Fast-path dedup — a nonce we've already SETTLED in-process is an immediate no-op.
    //    Read-only here (has, not markSeen): we only CONSUME the nonce after a successful
    //    atomicClose below, so a transient-retry (which reuses the stable `ref:settle` nonce)
    //    is never wrongly blocked. The durable guards (tx_id UNIQUE + atomicClose) are the
    //    authoritative idempotency across restarts/concurrency; this is just a fast path.
    if (seen.has(signed.nonce)) {
      log('info', `duplicate report (nonce seen) ref=${ref}`);
      return { status: 'duplicate', ref };
    }

    const facts = signed.facts || {};
    const callFacts = facts.callFacts || {};
    const payments = Array.isArray(facts.payments) ? facts.payments : [];

    // 4. Independently VERIFY each escrowed payment on-chain (the verified envelope).
    //    Collect the verified set; abort to 'retry' on a transient error BEFORE any close.
    const verified = [];
    for (const p of payments) {
      const currency = p.currency || config.currency;
      let v;
      try {
        v = await escrowCore.verifyPayment(
          { txId: p.txId, sender: p.sender, account: config.account, currency,
            expectedMemo: p.memo, expectedAmount: p.amount },
          { getTransaction: deps.getTransaction }
        );
      } catch (e) {
        if (isTransient(e)) return { status: 'retry', ref, reason: `verify ${p.txId}: ${e.message}` };
        log('warn', `dropping payment ${p.txId} (structural verify failure): ${e.message}`);
        continue; // forged / wrong-memo payment can't enter the envelope
      }
      // Hive-Engine tokens need the sidechain hard-confirm (Hive-layer broadcast succeeding
      // does NOT mean the sidechain accepted it). Defaults to the live escrow-core check;
      // tests inject a mock. Native HIVE/HBD skip it.
      const verifySidechain = deps.verifySidechain || escrowCore.verifySidechain;
      if (!escrowCore.isNativeCurrency(v.currency) && verifySidechain) {
        try { await verifySidechain(p.txId); }
        catch (e) { if (isTransient(e)) return { status: 'retry', ref, reason: `sidechain ${p.txId}: ${e.message}` };
                    log('warn', `dropping HE payment ${p.txId} (sidechain reject): ${e.message}`); continue; }
      }
      const purpose = (escrowCore.parseMemo(p.memo) || {}).purpose || p.purpose || 'deposit';
      verified.push({ v, purpose, memo: p.memo });
    }

    // 4b. Pre-commit guard for the combined-transfer re-split (Option B). The node may fund
    // ring+connect+deposit as ONE on-chain transfer and ASSERT the non-refundable ring/connect
    // portions via callFacts (applied in step 5b). Reject — BEFORE recording/closing anything,
    // so a corrected re-report can still settle — a report that asserts MORE ring+connect than
    // the verified deposit envelope holds (you can't re-split money that isn't there). An honest
    // node's assertions are always components of the verified deposit total; this only fires on a
    // malformed/adversarial report.
    const assertRing0    = Math.max(0, Number(callFacts.ringPaid)    || 0);
    const assertConnect0 = Math.max(0, Number(callFacts.connectPaid) || 0);
    if (assertRing0 + assertConnect0 > 0) {
      const depositVerified = verified.reduce((s, x) =>
        s + (DEPOSIT_PURPOSES.has(x.purpose) ? (Number(x.v.paid) || 0) : 0), 0);
      const guardFloor = Math.pow(10, -placesFor((verified[0] && verified[0].v.currency) || config.currency));
      if (assertRing0 + assertConnect0 > depositVerified + guardFloor) {
        return reject(ref, 'asserted_split_exceeds_deposit');
      }
    }

    // ── SYNCHRONOUS commit section (no await): record + single-winner close atomically. ──
    // A ref that ALREADY has a closed row is settled — ignore (this also blocks an attacker
    // appending a fresh payment to a settled ref to retrigger settlement).
    const pre = ledger.getPaymentsByRef(ref);
    if (pre.some(r => r.settle_state === 'closed')) {
      log('info', `ref ${ref} already settled — returning prior receipt`);
      return { status: 'already_settled', ref, receipt: receiptFromLedger(ref) };
    }
    for (const { v, memo, purpose } of verified) {
      // Base columns; the memo is what classifies the purpose (on-chain-verified).
      const row = { tx_id: v.txId, ref, sender: v.sender, currency: v.currency, amount: v.paid,
        memo, block_num: v.blockNum };
      // Per-call locked facts (node-asserted; only ever re-split the verified envelope) are
      // persisted on the DEPOSIT rows so a crash-recovering box can settle without the report.
      if (DEPOSIT_PURPOSES.has(purpose)) {
        if (callFacts.ratePerHour  != null) row.rate_per_hour = Number(callFacts.ratePerHour);
        if (callFacts.startTs      != null) row.start_ts      = Number(callFacts.startTs);
        if (callFacts.platformFee  != null) row.platform_fee  = Number(callFacts.platformFee);
        if (callFacts.callee       != null) row.callee        = callFacts.callee;
      }
      try {
        ledger.recordPayment(row);
      } catch (e) {
        if (e && e.code === 'conflict') continue; // tx already recorded — idempotent
        throw e;
      }
    }
    const payRows = ledger.getPaymentsByRef(ref);
    if (payRows.length === 0) {
      log('warn', `ref ${ref} has no verified payments — nothing to settle`);
      return { status: 'rejected', ref, reason: 'no_verified_payments' };
    }
    if (!ledger.atomicClose(ref)) {
      log('info', `ref ${ref} lost atomicClose race — already settling/settled`);
      return { status: 'already_settled', ref, receipt: receiptFromLedger(ref) };
    }
    seen.markSeen(signed.nonce); // we won the close → consume the nonce (in-process fast-path)
    // ── end synchronous commit section ──

    // 5. Derive money facts from the DURABLE rows (the authority), classified by verified memo.
    const bucket = { ring: 0, connect: 0, deposit: 0 };
    for (const r of payRows) {
      const purpose = (escrowCore.parseMemo(r.memo) || {}).purpose || 'deposit';
      if (purpose === 'ring') bucket.ring += Number(r.amount) || 0;
      else if (purpose === 'connect') bucket.connect += Number(r.amount) || 0;
      else bucket.deposit += Number(r.amount) || 0; // call/deposit/topup/unknown → refundable cap
    }
    const primary = payRows.find(r => r.rate_per_hour != null) || payRows[0];
    const currency    = primary.currency || config.currency;
    const ratePerHour = Number(primary.rate_per_hour) || 0;
    const platformFee = (primary.platform_fee != null) ? Number(primary.platform_fee) : 0.10;
    const callee      = primary.callee || callFacts.callee;
    const caller      = primary.sender;
    const startTs     = (primary.start_ts != null) ? Number(primary.start_ts) : Number(callFacts.startTs) || 0;
    const places      = placesFor(currency);
    const floor       = Math.pow(10, -places);
    const now         = nowFn();

    // 5b. Combined-transfer re-split. When the node funds ring+connect+deposit as ONE on-chain
    // transfer, ring/connect arrive folded INTO the deposit bucket (a single deposit-purpose,
    // on-chain-verified payment). The node ASSERTS how much of that verified deposit total is
    // actually the non-refundable ring (→fee) / connect (→callee) via callFacts. We only ever
    // CARVE these OUT of the already-verified deposit bucket — the envelope total
    // (ring+connect+deposit == V) is unchanged, so a lying assertion can only RE-SPLIT, never
    // mint. (Additive with the memo classification above: when ring/connect were their own
    // on-chain transfers, callFacts carries no assertion and this is a no-op.) An assertion that
    // tries to carve more than the verified deposit holds is rejected.
    // (Validated pre-commit at 4b — carve <= verified deposit; here we just apply it to the
    // durable-row buckets. ring/connect each gain exactly the asserted amount and deposit loses
    // their sum, so the envelope total is unchanged; Math.max(0,…) only absorbs sub-floor
    // rounding noise.)
    const assertRing    = Math.max(0, Number(callFacts.ringPaid)    || 0);
    const assertConnect = Math.max(0, Number(callFacts.connectPaid) || 0);
    const carve = assertRing + assertConnect;
    if (carve > 0) {
      bucket.ring    = escrowCore.roundCoins(bucket.ring + assertRing, currency, places);
      bucket.connect = escrowCore.roundCoins(bucket.connect + assertConnect, currency, places);
      bucket.deposit = Math.max(0, escrowCore.roundCoins(bucket.deposit - carve, currency, places));
    }

    // 6. Cap (the money-safety invariant) — computed by escrow-core.settle, never inline.
    const meteredUsage = adapter.meteredUsage(
      { rate_per_hour: ratePerHour, start_ts: startTs, max_duration_min: config.maxDurationMin }, now);
    const settled = escrowCore.settle({ deposit: bucket.deposit, meteredUsage, currency, places, dustFloor: floor });
    const durationMin = startTs ? Math.min((now - startTs) / 60000, config.maxDurationMin || Infinity) : 0;

    // 7. v4call split (payout/refund/fee) — the adapter's per-service seam; conserves the envelope.
    const split = adapter.settlementSplit(
      { connect_paid: bucket.connect, ring_paid: bucket.ring, platform_fee: platformFee,
        callee, caller, currency },
      settled,
      { ref, feeAccount: config.feeAccount, durationMin, places }
    );

    // 8. Durable refund lifecycle → disburse with the box key → mark sent/pending/failed.
    let payoutTx = null, overall = 'settled';
    for (const o of split.outflows) {
      const { refund_id } = ledger.recordRefund({
        ref, to_account: o.to_account, amount: o.amount, currency: o.currency, memo: o.memo, reason: o.reason });
      try {
        const { txId } = await escrowCore.disburse(
          { to: o.to_account, amount: o.amount, currency: o.currency, memo: o.memo,
            fromAccount: config.account, keyEnv: config.keyEnv, places },
          { client: deps.broadcastClient }
        );
        ledger.markRefundSettled(refund_id, 'sent', txId);
        o.txId = txId; o.status = 'sent';
        if (o.kind === 'payout') payoutTx = txId;
      } catch (e) {
        if (e && e.code === 'no_key') {
          // leave the refund row 'pending' for manual/again settlement — NEVER double-paid
          o.status = 'pending'; if (overall === 'settled') overall = 'pending';
          log('error', `disburse ${o.kind} → ${o.to_account} has no key: row left pending`);
        } else {
          ledger.markRefundSettled(refund_id, 'failed', null);
          o.status = 'failed'; overall = 'failed';
          log('error', `disburse ${o.kind} → ${o.to_account} FAILED: ${e.message}`);
        }
      }
    }

    // 9. Signed settlement-receipt back to the node.
    const receipt = escrowCore.buildSettlementReceipt({
      ref, settlement: settled.settlement, refund: settled.refund, dust: settled.dust,
      currency, disburseTx: payoutTx, status: overall, createdAt: now });
    const signedReceipt = boxSkHex ? escrowCore.signReport(receipt, boxSkHex) : receipt;

    log('info', `settled ${ref}: payout/refund/fee, status=${overall}`);
    return { status: overall, ref, receipt: signedReceipt, outflows: split.outflows };
  }

  // Crash-recovery: disburse any refund rows still 'pending' (e.g. a box that died after
  // atomicClose+recordRefund but before disburse, or a no_key that was later provisioned).
  // Mirrors escrow-core/scripts/dry-run-adversarial.js's recover phase. Idempotent.
  async function disbursePending() {
    const pending = ledger.db.prepare("SELECT * FROM refunds WHERE status = 'pending'").all();
    let done = 0;
    for (const r of pending) {
      try {
        const { txId } = await escrowCore.disburse(
          { to: r.to_account, amount: r.amount, currency: r.currency, memo: r.memo,
            fromAccount: config.account, keyEnv: config.keyEnv, places: placesFor(r.currency) },
          { client: deps.broadcastClient }
        );
        ledger.markRefundSettled(r.refund_id, 'sent', txId);
        done++;
      } catch (e) {
        if (e && e.code === 'no_key') { log('error', `recovery: ${r.refund_id} still no key — left pending`); continue; }
        ledger.markRefundSettled(r.refund_id, 'failed', null);
        log('error', `recovery: ${r.refund_id} failed: ${e.message}`);
      }
    }
    if (done) log('info', `recovery disbursed ${done} pending refund(s)`);
    return done;
  }

  // Wire the injected transport: every inbound event-report → handleReport → publish the receipt.
  async function start() {
    await disbursePending(); // settle anything left mid-flight before taking new work
    if (deps.transport && deps.transport.subscribe) {
      deps.transport.subscribe(async (signed) => {
        const out = await handleReport(signed);
        if (out.receipt && deps.transport.publish) await deps.transport.publish(out.receipt, { to: signed.pubkey });
      });
      log('info', 'escrow box listening for event-reports');
    }
  }

  return { handleReport, disbursePending, start, _seen: seen };
}

module.exports = { createEscrowBox, DEPOSIT_PURPOSES };
