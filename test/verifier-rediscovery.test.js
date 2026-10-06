/**
 * A long-running client across a change of verifier.
 *
 * The verified path signs a message that names the verifier contract, and the
 * registry can move to another verifier with one transaction (setRelay). A
 * client that kept the verifier address for its whole life went on signing
 * for the old one after such a move, and every write was refused
 * BAD_SIGNATURE until the process restarted. Tested here:
 *
 *   (a) after the discovery TTL a long-lived client asks again and signs for
 *       the new verifier, with no refusal and no restart
 *   (b) inside the TTL, a refusal a stale verifier can cause makes the client
 *       forget the verifier (its own answer and the shared one), ask again,
 *       re-read the nonce, re-sign, and the one retry lands
 *   (c) a refusal of the retry is returned, never retried again
 *   (d) a refusal a stale verifier cannot cause, or an answer that may follow
 *       a transaction, is never retried
 *   (e) all of it for ML-DSA-65 and ML-DSA-87
 *   (f) nothing changes when nothing changes
 *   (g) a probe that failed (no connection, a proxy's 502, a relay that could
 *       not read the chain) is not remembered, so a client whose first probe
 *       failed is not kept on v1 for its whole life; a relay's own "not cut
 *       over" is still believed for the TTL
 *
 * The relay here behaves like the chain behind it: it rebuilds the message for
 * whichever verifier it currently names, verifies the real signature, and holds
 * a nonce per verifier per key. So a refusal below is earned, not scripted,
 * except where a test forces one to see what the client does with it.
 */

import { createServer } from 'node:http'
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { mlDsa, mlDsa87, fingerprint } from 'kxco-post-quantum'
import { KxcoChain, authorisingMessage, INTENT_V2_ARGS, OPERATION_TAGS } from '../src/index.js'

const CHAIN_ID = 1111111
const TTL_MS = 5 * 60_000
const V1 = '0x1111111111111111111111111111111111111111'
const V2 = '0x2222222222222222222222222222222222222222'
const V3 = '0x3333333333333333333333333333333333333333'
const BOTH = ['ML-DSA-65', 'ML-DSA-87']

const SETS = {
  'ML-DSA-65': { mod: mlDsa, kp: mlDsa.keypairFromMaster(Buffer.alloc(32, 0x65), 'rediscovery') },
  'ML-DSA-87': { mod: mlDsa87, kp: mlDsa87.keypairFromMaster(Buffer.alloc(32, 0x87), 'rediscovery') },
}

function identityFor(set) {
  const { mod, kp } = SETS[set]
  return {
    kid: fingerprint(kp.publicKey),
    publicKeyHex: Buffer.from(kp.publicKey).toString('hex'),
    sign: async (message) => Buffer.from(mod.sign(kp.secretKey, message), 'hex'),
  }
}

const KEY_SET = { 1952: 'ML-DSA-65', 2592: 'ML-DSA-87' }

/**
 * A relay and the chain behind it, reduced to what this defect touches.
 *
 * `state.verifier` is what registry.relay() names now; switching it is the
 * setRelay transaction. `force` queues answers for POST /intents/v2 that
 * replace the chain's own judgement. `paramsFail` makes the next N probes drop
 * the connection, and `paramsAnswers` queues raw answers for the next probes. `afterParams` and `afterNonce` run once after the next such
 * answer is sent, to change the world between two of the client's requests.
 */
async function chainRelay({ verifier = V1, algorithms = BOTH, verified = true } = {}) {
  const state = {
    verifier, algorithms, verified,
    nonces: new Map(), writes: [], log: [], force: [], paramsFail: 0, paramsAnswers: [],
    afterParams: null, afterNonce: null, v1Answer: null,
  }
  const nonceOf = (kid) => state.nonces.get(`${state.verifier}:${kid}`) ?? 0

  const server = createServer(async (req, res) => {
    const entry = { method: req.method, path: req.url.replace(/\/nonce\/.*/, '/nonce'), status: 0, code: null }
    state.log.push(entry)
    const json = (status, body) => {
      entry.status = status
      entry.code = body.code ?? null
      res.writeHead(status, { 'content-type': 'application/json' })
      res.end(JSON.stringify(body))
    }

    if (req.method === 'GET' && req.url === '/intents/v2/params') {
      if (state.paramsFail > 0) { state.paramsFail--; entry.status = 'dropped'; return req.socket.destroy() }
      if (state.paramsAnswers.length) {
        const a = state.paramsAnswers.shift()
        entry.status = a.status
        entry.code = a.body?.code ?? null
        res.writeHead(a.status, { 'content-type': a.body ? 'application/json' : 'text/html' })
        return res.end(a.body ? JSON.stringify(a.body) : a.raw)
      }
      if (!state.verified) return json(503, { ok: false, code: 'VERIFIED_PATH_UNAVAILABLE' })
      json(200, { ok: true, verifyingRelay: state.verifier, chainId: CHAIN_ID, algorithms: state.algorithms })
      const after = state.afterParams; state.afterParams = null; after?.()
      return
    }
    if (req.method === 'GET' && req.url.startsWith('/intents/v2/nonce/')) {
      json(200, { ok: true, nonce: nonceOf(req.url.split('/').pop()) })
      const after = state.afterNonce; state.afterNonce = null; after?.()
      return
    }

    let raw = ''
    for await (const chunk of req) raw += chunk
    const intent = JSON.parse(raw)
    entry.intent = intent

    if (req.url === '/intents') {
      return state.v1Answer
        ? json(state.v1Answer.status, state.v1Answer.body)
        : json(200, { ok: true, txHash: '0x' + 'f1'.repeat(32), blockNumber: 1, chainId: CHAIN_ID })
    }

    // POST /intents/v2
    if (state.force.length) {
      const f = state.force.shift()
      if (f === 'drop') { entry.status = 'dropped'; return req.socket.destroy() }
      return json(f.status, { ok: false, ...f.body })
    }
    const set = KEY_SET[intent.publicKeyHex.length / 2]
    if (set === 'ML-DSA-87' && !state.algorithms.includes('ML-DSA-87')) {
      return json(400, { ok: false, code: 'ALG_NOT_VERIFIED_ON_CHAIN', error: 'this verifier checks ML-DSA-65 only' })
    }
    const kid = intent.institutionKid
    if (intent.nonce !== nonceOf(kid)) {
      return json(409, { ok: false, code: 'BAD_NONCE', error: 'nonce is not the next one for this key' })
    }
    const message = authorisingMessage({
      relayAddress: state.verifier, operationTag: OPERATION_TAGS.anchorAttestation, kid, nonce: intent.nonce,
      args: INTENT_V2_ARGS.anchorAttestation(intent.payload.payloadHash, intent.payload.purpose),
      chainId: CHAIN_ID, ...(set === 'ML-DSA-87' ? { alg: set } : {}),
    })
    const publicKey = Buffer.from(intent.publicKeyHex, 'hex')
    if (!SETS[set].mod.verify(publicKey, message, intent.signature)) {
      return json(403, { ok: false, code: 'BAD_SIGNATURE', error: 'the chain rejected the signature' })
    }
    state.nonces.set(`${state.verifier}:${kid}`, intent.nonce + 1)
    state.writes.push({ verifier: state.verifier, kid, nonce: intent.nonce, payloadHash: intent.payload.payloadHash })
    json(200, {
      ok: true, txHash: '0x' + state.writes.length.toString(16).padStart(64, '0'),
      blockNumber: state.writes.length, chainId: CHAIN_ID, verifiedOnChain: true,
    })
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))

  const count = (from, method, path, status) => state.log.slice(from).filter((e) =>
    e.method === method && e.path === path && (status === undefined || e.status === status)).length
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    state,
    /** setRelay: the registry names another verifier. */
    switchTo(address, algorithms = state.algorithms) { state.verifier = address; state.algorithms = algorithms },
    mark: () => state.log.length,
    probes: (from = 0) => count(from, 'GET', '/intents/v2/params'),
    posts: (from = 0) => count(from, 'POST', '/intents/v2'),
    refusals: (from = 0) => state.log.slice(from).filter((e) => e.method === 'POST' && e.status !== 200).length,
    trail: (from = 0) => state.log.slice(from).map((e) => `${e.method} ${e.path} ${e.status}${e.code ? ' ' + e.code : ''}`),
    close: () => new Promise((r) => server.close(r)),
  }
}

const client = (url, set, extra = {}) =>
  new KxcoChain({ relay: url, identity: identityFor(set), licenceKey: 'test-licence', ...extra })

let beat = 0
const anchor = (c) => c.anchorAttestation({ payloadHash: (++beat).toString(16).padStart(64, '0'), purpose: 'system-test' })

/** No (verifier, kid, nonce) twice, and one write per call that succeeded. */
function assertNoDoubleWrite(r, succeeded) {
  const seen = new Set(r.state.writes.map((w) => `${w.verifier}:${w.kid}:${w.nonce}`))
  assert.equal(seen.size, r.state.writes.length, 'a nonce was spent twice')
  assert.equal(r.state.writes.length, succeeded, `expected ${succeeded} writes on the chain, found ${r.state.writes.length}`)
}

// ── (a) the TTL ─────────────────────────────────────────────────────────────

for (const set of BOTH) {
  test(`${set}: after the TTL a long-lived client signs for the new verifier, with no refusal and no restart`, async (t) => {
    t.mock.timers.enable({ apis: ['Date'], now: Date.now() })
    const r = await chainRelay()
    try {
      const c = client(r.url, set)
      await anchor(c)
      assert.equal(r.state.writes[0].verifier, V1)

      r.switchTo(V2)
      t.mock.timers.tick(TTL_MS + 1)
      const m = r.mark()
      const res = await anchor(c)

      assert.deepEqual(r.trail(m), ['GET /intents/v2/params 200', 'GET /intents/v2/nonce 200', 'POST /intents/v2 200'],
        'the client must ask again once its answer is older than the TTL, before it signs')
      assert.equal(r.state.writes[1].verifier, V2)
      assert.equal(r.state.writes[1].nonce, 0, "V2's nonce, read after the move")
      assert.equal(res.blockNumber, 2)
      assertNoDoubleWrite(r, 2)
    } finally { await r.close() }
  })

  test(`${set}: a client that adopted the shared answer expires with it, not a TTL after adopting it`, async (t) => {
    t.mock.timers.enable({ apis: ['Date'], now: Date.now() })
    const r = await chainRelay()
    try {
      await anchor(client(r.url, set))             // probes, fills the shared cache
      t.mock.timers.tick(TTL_MS - 60_000)
      const late = client(r.url, set)
      await anchor(late)                           // adopts the shared answer, no probe
      assert.equal(r.probes(), 1)

      r.switchTo(V2)
      t.mock.timers.tick(60_000 + 1)               // the shared answer is now out of date
      const m = r.mark()
      await anchor(late)
      assert.equal(r.refusals(m), 0, 'the adopted answer outlived the shared one, so the client signed for the old verifier')
      assert.equal(r.probes(m), 1)
      assert.equal(r.state.writes.at(-1).verifier, V2)
    } finally { await r.close() }
  })
}

// ── (b) a stale-verifier refusal inside the TTL: rediscover, retry once ─────

for (const set of BOTH) {
  test(`${set}: inside the TTL, BAD_SIGNATURE after a verifier change is followed by one rediscovery and one retry that lands`, async () => {
    const r = await chainRelay()
    try {
      const c = client(r.url, set)
      await anchor(c)

      r.switchTo(V2)                               // setRelay, well inside the TTL
      const m = r.mark()
      const res = await anchor(c)

      assert.deepEqual(r.trail(m), [
        'GET /intents/v2/nonce 200', 'POST /intents/v2 403 BAD_SIGNATURE',
        'GET /intents/v2/params 200', 'GET /intents/v2/nonce 200', 'POST /intents/v2 200',
      ])
      assert.equal(r.state.writes[1].verifier, V2)
      assert.equal(res.txHash, '0x' + '2'.padStart(64, '0'))
      assertNoDoubleWrite(r, 2)

      // The shared answer was replaced too: a new client, still inside the
      // TTL, signs for V2 without a refusal and without asking again.
      const m2 = r.mark()
      await anchor(client(r.url, set))
      assert.equal(r.refusals(m2), 0, 'a new client was handed the stale shared answer')
      assert.equal(r.probes(m2), 0)

      // And back: rolling the registry back is recovered from the same way.
      r.switchTo(V1)
      const m3 = r.mark()
      await anchor(c)
      assert.equal(r.posts(m3), 2)
      assert.equal(r.state.writes.at(-1).verifier, V1)
      assert.equal(r.state.writes.at(-1).nonce, 1, "V1's own next nonce")
      assertNoDoubleWrite(r, 4)
    } finally { await r.close() }
  })

  test(`${set}: BAD_NONCE, another writer having used the nonce, is retried once with the next nonce`, async () => {
    const r = await chainRelay()
    try {
      const c = client(r.url, set)
      await anchor(c)
      const kid = identityFor(set).kid
      // Another process with this key writes between this client's nonce read
      // and its POST.
      r.state.afterNonce = () => r.state.nonces.set(`${V1}:${kid}`, 2)
      const m = r.mark()
      await anchor(c)

      assert.deepEqual(r.trail(m), [
        'GET /intents/v2/nonce 200', 'POST /intents/v2 409 BAD_NONCE',
        'GET /intents/v2/params 200', 'GET /intents/v2/nonce 200', 'POST /intents/v2 200',
      ])
      assert.equal(r.state.writes.at(-1).nonce, 2, 'the retry must sign the nonce read after the refusal')
      assertNoDoubleWrite(r, 2)
    } finally { await r.close() }
  })
}

test('ML-DSA-87: ALG_NOT_VERIFIED_ON_CHAIN after a rollback to an ML-DSA-65-only verifier rediscovers, then goes v1.1', async () => {
  const r = await chainRelay({ verifier: V2, algorithms: BOTH })
  try {
    const c = client(r.url, 'ML-DSA-87')
    await anchor(c)
    r.switchTo(V1, ['ML-DSA-65'])
    const m = r.mark()
    await anchor(c)

    assert.deepEqual(r.trail(m), [
      'GET /intents/v2/nonce 200', 'POST /intents/v2 400 ALG_NOT_VERIFIED_ON_CHAIN',
      'GET /intents/v2/params 200', 'POST /intents 200',
    ])
    const last = r.state.log.at(-1).intent
    assert.equal(last.alg, 'ML-DSA-87')
    assert.ok(last.timestamp, 'a v1.1 intent, as a client that had just asked would send')
  } finally { await r.close() }
})

// ── (c) the retry is the last attempt ───────────────────────────────────────

for (const set of BOTH) {
  test(`${set}: a refusal of the retry is returned, not retried again`, async () => {
    const r = await chainRelay()
    try {
      const c = client(r.url, set)
      await anchor(c)

      // The registry moves twice: once before the write, and again between
      // the rediscovery and the retry.
      r.switchTo(V2)
      r.state.afterParams = () => r.switchTo(V3)
      const m = r.mark()
      await assert.rejects(() => anchor(c), (e) => e.code === 'BAD_SIGNATURE' && e.status === 403)
      assert.equal(r.posts(m), 2, 'one attempt and one retry, no more')
      assert.equal(r.probes(m), 1, 'one rediscovery')
      assertNoDoubleWrite(r, 1)

      // Forced: two refusals in a row.
      r.state.force.push({ status: 409, body: { code: 'BAD_NONCE' } }, { status: 409, body: { code: 'BAD_NONCE' } })
      const m2 = r.mark()
      await assert.rejects(() => anchor(c), (e) => e.code === 'BAD_NONCE' && e.status === 409)
      assert.equal(r.posts(m2), 2)
      assertNoDoubleWrite(r, 1)

      // The client is not left broken: the next write finds V3.
      await anchor(c)
      assert.equal(r.state.writes.at(-1).verifier, V3)
      assertNoDoubleWrite(r, 2)
    } finally { await r.close() }
  })
}

// ── (d) what is never retried ───────────────────────────────────────────────

const NOT_STALE = [
  [403, 'ALG_MISMATCH'], [403, 'UNKNOWN_INSTITUTION'], [403, 'PUBLIC_KEY_MISMATCH'], [403, 'NOT_OWNER'],
  [400, 'INVALID_INTENT'], [400, 'MISSING_NONCE'], [400, 'UNSUPPORTED_ALG'], [400, 'UNSUPPORTED_PUBLIC_KEY'],
  [400, 'UNKNOWN_OPERATION'], [401, 'LICENCE_REJECTED'], [410, 'USE_VERIFIED_PATH'],
  [503, 'ALG_NOT_ACTIVE_ON_CHAIN'], [503, 'VERIFIED_PATH_UNAVAILABLE'], [503, 'CHAIN_UNAVAILABLE'],
  [500, 'RELAY_ERROR'], [500, 'CALL_EXCEPTION'],
]

// A stale-verifier code on an answer that may follow a transaction: with a
// hash, with a 5xx, or with a 2xx. None of these is the relay's pre-send refusal.
const MAY_HAVE_SENT = [
  [403, 'BAD_SIGNATURE', { txHash: '0x' + 'ab'.repeat(32) }],
  [409, 'BAD_NONCE', { txHash: '0x' + 'ab'.repeat(32) }],
  [500, 'BAD_SIGNATURE', {}],
  [502, 'BAD_NONCE', {}],
  [200, 'BAD_SIGNATURE', {}],
]

for (const set of BOTH) {
  test(`${set}: a refusal a stale verifier cannot cause is returned at once`, async () => {
    const r = await chainRelay()
    try {
      const c = client(r.url, set)
      await anchor(c)
      for (const [status, code] of NOT_STALE) {
        r.state.force.push({ status, body: { code, error: code } })
        const m = r.mark()
        await assert.rejects(() => anchor(c), (e) => e.code === code, code)
        assert.equal(r.posts(m), 1, `${status} ${code} was retried`)
        assert.equal(r.probes(m), 0, `${status} ${code} made the client rediscover`)
      }
      assertNoDoubleWrite(r, 1)
    } finally { await r.close() }
  })

  test(`${set}: an answer that may follow a transaction is never retried, whatever its code`, async () => {
    const r = await chainRelay()
    try {
      const c = client(r.url, set)
      await anchor(c)
      for (const [status, code, extra] of MAY_HAVE_SENT) {
        r.state.force.push({ status, body: { code, error: code, ...extra } })
        const m = r.mark()
        await assert.rejects(() => anchor(c), (e) => e.code === code, `${status} ${code}`)
        assert.equal(r.posts(m), 1, `${status} ${code} ${JSON.stringify(extra)} was retried`)
      }
      // A connection lost after the POST went out: the relay may have sent it.
      r.state.force.push('drop')
      const m = r.mark()
      await assert.rejects(() => anchor(c), (e) => e.code === 'NETWORK_ERROR')
      assert.equal(r.posts(m), 1, 'a lost connection was retried')
    } finally { await r.close() }
  })
}

// ── the same staleness the other way: v1 sent, the relay says use v2 ───────

test('ML-DSA-65: a cutover inside the TTL is followed at once: 410 USE_VERIFIED_PATH, one rediscovery, v2', async () => {
  const r = await chainRelay({ verified: false })
  try {
    const c = client(r.url, 'ML-DSA-65')
    await anchor(c)                                // v1, and "not cut over" is believed
    r.state.verified = true                        // setRelay(V1): the cutover
    r.state.v1Answer = { status: 410, body: { ok: false, code: 'USE_VERIFIED_PATH', error: 'Use POST /intents/v2' } }
    const m = r.mark()
    await anchor(c)
    assert.deepEqual(r.trail(m), [
      'POST /intents 410 USE_VERIFIED_PATH',
      'GET /intents/v2/params 200', 'GET /intents/v2/nonce 200', 'POST /intents/v2 200',
    ])
    assertNoDoubleWrite(r, 1)
  } finally { await r.close() }
})

test('ML-DSA-87: switching ML-DSA-87 on inside the TTL is followed at once, on the same client', async () => {
  const r = await chainRelay({ algorithms: ['ML-DSA-65'] })
  try {
    const c = client(r.url, 'ML-DSA-87')
    await anchor(c)                                // v1.1: ML-DSA-87 not yet verified on-chain
    assert.equal(r.trail().at(-1), 'POST /intents 200')
    r.state.algorithms = BOTH                      // the activation block passes
    r.state.v1Answer = { status: 410, body: { ok: false, code: 'USE_VERIFIED_PATH', error: 'Use POST /intents/v2' } }
    const m = r.mark()
    await anchor(c)
    assert.deepEqual(r.trail(m), [
      'POST /intents 410 USE_VERIFIED_PATH',
      'GET /intents/v2/params 200', 'GET /intents/v2/nonce 200', 'POST /intents/v2 200',
    ])
    assert.equal(r.state.log.at(-1).intent.alg, 'ML-DSA-87')
    assertNoDoubleWrite(r, 1)
  } finally { await r.close() }
})

test('USE_VERIFIED_PATH is not retried by a client pinned to v1, nor more than once', async () => {
  const r = await chainRelay({ verified: false })
  try {
    r.state.v1Answer = { status: 410, body: { ok: false, code: 'USE_VERIFIED_PATH' } }
    await assert.rejects(() => anchor(client(r.url, 'ML-DSA-65', { verifiedPath: false })), (e) => e.code === 'USE_VERIFIED_PATH')
    assert.deepEqual(r.trail(), ['POST /intents 410 USE_VERIFIED_PATH'])

    // The relay says use v2 but its params still say it has not cut over.
    const m = r.mark()
    await assert.rejects(() => anchor(client(r.url, 'ML-DSA-65')), (e) => e.code === 'USE_VERIFIED_PATH')
    assert.equal(r.trail(m).filter((t) => t.startsWith('POST')).length, 2, 'one attempt and one retry, no more')
  } finally { await r.close() }
})

test('a BAD_SIGNATURE on v1 is not a verifier question and is not retried', async () => {
  const r = await chainRelay({ verified: false })
  try {
    r.state.v1Answer = { status: 401, body: { ok: false, code: 'BAD_SIGNATURE', error: 'signature does not verify' } }
    const c = client(r.url, 'ML-DSA-65')
    const m = r.mark()
    await assert.rejects(() => anchor(c), (e) => e.code === 'BAD_SIGNATURE')
    assert.deepEqual(r.trail(m), ['GET /intents/v2/params 503 VERIFIED_PATH_UNAVAILABLE', 'POST /intents 401 BAD_SIGNATURE'])
  } finally { await r.close() }
})

// ── (f) nothing changes when nothing changes ───────────────────────────────

for (const set of BOTH) {
  test(`${set}: with no verifier change, one probe per TTL and no extra requests`, async (t) => {
    t.mock.timers.enable({ apis: ['Date'], now: Date.now() })
    const r = await chainRelay()
    try {
      const c = client(r.url, set)
      for (let i = 0; i < 3; i++) {
        await anchor(c)
        t.mock.timers.tick(60_000)
      }
      assert.deepEqual(r.trail(), [
        'GET /intents/v2/params 200',
        'GET /intents/v2/nonce 200', 'POST /intents/v2 200',
        'GET /intents/v2/nonce 200', 'POST /intents/v2 200',
        'GET /intents/v2/nonce 200', 'POST /intents/v2 200',
      ])
      t.mock.timers.tick(TTL_MS)
      const m = r.mark()
      await anchor(c)
      assert.deepEqual(r.trail(m), ['GET /intents/v2/params 200', 'GET /intents/v2/nonce 200', 'POST /intents/v2 200'])
      assert.deepEqual(r.state.writes.map((w) => `${w.verifier}:${w.nonce}`), [0, 1, 2, 3].map((n) => `${V1}:${n}`))
    } finally { await r.close() }
  })
}

test('verifiedPath false stays on v1 for the life of the client, past any TTL', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.now() })
  const r = await chainRelay()
  try {
    const c = client(r.url, 'ML-DSA-65', { verifiedPath: false })
    await anchor(c)
    t.mock.timers.tick(TTL_MS * 3)
    await anchor(c)
    assert.deepEqual(r.trail(), ['POST /intents 200', 'POST /intents 200'])
  } finally { await r.close() }
})

test('a probe that could not reach the relay is not remembered by the client', async () => {
  // The shared cache already declined to keep a transport failure. The client
  // used to keep it for its whole life, pinning a long-running process to v1
  // after one dropped connection.
  const r = await chainRelay()
  try {
    r.state.paramsFail = 1
    const c = client(r.url, 'ML-DSA-65')
    await anchor(c)
    assert.deepEqual(r.trail(), ['GET /intents/v2/params dropped', 'POST /intents 200'])
    const m = r.mark()
    await anchor(c)
    assert.deepEqual(r.trail(m), ['GET /intents/v2/params 200', 'GET /intents/v2/nonce 200', 'POST /intents/v2 200'])
  } finally { await r.close() }
})

test('a refused write whose rediscovery cannot reach the relay leaves no stale shared answer behind', async () => {
  const r = await chainRelay()
  try {
    const c = client(r.url, 'ML-DSA-65')
    await anchor(c)

    r.switchTo(V2)
    r.state.paramsFail = 1                         // the rediscovery is dropped
    r.state.v1Answer = { status: 410, body: { ok: false, code: 'USE_VERIFIED_PATH' } }
    await assert.rejects(() => anchor(c), (e) => e.code === 'USE_VERIFIED_PATH')

    // Still inside the TTL. A new client must ask, not adopt the V1 answer.
    const m = r.mark()
    await anchor(client(r.url, 'ML-DSA-65'))
    assert.equal(r.refusals(m), 0, 'the shared cache still held the replaced verifier')
    assert.equal(r.probes(m), 1)
    assert.equal(r.state.writes.at(-1).verifier, V2)
  } finally { await r.close() }
})

test('a probe answered with a failure, not a verdict, is not remembered by the client or the process', async () => {
  // A proxy answering 502 while the relay restarts behind it, and a relay
  // that could not read the chain, have said nothing about the verified path.
  const FAILED = [
    { status: 502, raw: '<html><body>502 Bad Gateway</body></html>' },
    { status: 503, body: { ok: false, code: 'CHAIN_UNAVAILABLE', error: 'could not read the chain' } },
    { status: 500, body: { ok: false } },
  ]
  for (const answer of FAILED) {
    const r = await chainRelay()
    try {
      r.state.paramsAnswers.push(answer)
      const c = client(r.url, 'ML-DSA-65')
      await anchor(c)
      const label = `${answer.status} ${answer.body?.code ?? ''}`
      assert.equal(r.trail()[1], 'POST /intents 200', `${label}: this write fell back to v1`)
      const m = r.mark()
      await anchor(c)
      assert.deepEqual(r.trail(m), ['GET /intents/v2/params 200', 'GET /intents/v2/nonce 200', 'POST /intents/v2 200'],
        `${label}: the client remembered a failed probe`)
    } finally { await r.close() }

    // Nor does the shared cache keep it: a second client in the process asks.
    const r2 = await chainRelay()
    try {
      r2.state.paramsAnswers.push(answer)
      await anchor(client(r2.url, 'ML-DSA-65'))
      await anchor(client(r2.url, 'ML-DSA-65'))
      assert.equal(r2.probes(), 2, `${answer.status}: the shared cache remembered a failed probe`)
      assert.equal(r2.state.writes.length, 1)
    } finally { await r2.close() }
  }
})

test('a relay that says it has not cut over is still believed for the TTL', async () => {
  // The control for the test above: 503 VERIFIED_PATH_UNAVAILABLE is the
  // relay's own answer, and is cached as before.
  const r = await chainRelay()
  try {
    r.state.paramsAnswers.push({ status: 503, body: { ok: false, code: 'VERIFIED_PATH_UNAVAILABLE' } })
    const c = client(r.url, 'ML-DSA-65')
    await anchor(c)
    await anchor(c)
    await anchor(client(r.url, 'ML-DSA-65'))
    assert.deepEqual(r.trail(), [
      'GET /intents/v2/params 503 VERIFIED_PATH_UNAVAILABLE', 'POST /intents 200', 'POST /intents 200', 'POST /intents 200',
    ])
  } finally { await r.close() }
})
