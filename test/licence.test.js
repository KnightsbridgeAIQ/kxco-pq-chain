// The licence gate, the chain-id assertion, and the intents added in 2.0.0.
//
// These are the behaviours a customer's integration will actually hit on the
// day they point at the hosted relay, so they are tested against a real HTTP
// server on loopback rather than a stubbed fetch.

import { createServer } from 'node:http'
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { mlDsa, fingerprint } from 'kxco-post-quantum'
import { KxcoChain, KxcoChainError, CHAIN_ID, DEFAULT_RELAY_URL } from '../src/index.js'

const LICENCE = 'kxco_live_0123456789abcdef'

function identity() {
  const keypair = mlDsa.ml_dsa65.keygen()
  return {
    kid: fingerprint(keypair.publicKey),
    publicKey: keypair.publicKey,
    async sign(message) {
      return Buffer.from(mlDsa.sign(keypair.secretKey, message), 'hex')
    },
  }
}

/**
 * @param {(req: object, headers: object) => object|number} respond
 *   Returns the JSON body to send, or an HTTP status to fail with.
 */
async function relay(respond = () => ({ ok: true, txHash: '0x' + 'ab'.repeat(32), blockNumber: 1, chainId: CHAIN_ID })) {
  const seen = []
  const server = createServer(async (req, res) => {
    let body = ''
    for await (const chunk of req) body += chunk

    // A v2-capable client probes GET /intents/v2/params before its first
    // write. This mock is a v1 relay, so answer 503 the way one does. Falling
    // through to JSON.parse('') threw inside the handler, the response never
    // came, and every test sat until its timeout.
    if (req.method === 'GET') {
      res.writeHead(503, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: false, code: 'VERIFIED_PATH_UNAVAILABLE' }))
      return
    }

    const intent = JSON.parse(body)
    seen.push({ intent, headers: req.headers })

    const out = respond(intent, req.headers)
    if (typeof out === 'number') {
      res.writeHead(out, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error: 'refused' }))
      return
    }
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(out))
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    seen,
    last: () => seen.at(-1),
    close: () => new Promise((r) => server.close(r)),
  }
}

// ── the licence gate ────────────────────────────────────────────────────────

// The failure that matters is shipping to production with no licence
// configured, and it should surface at boot rather than at the first write.
test('a hosted relay without a licence fails at construction, not at the first write', () => {
  assert.throws(
    () => new KxcoChain({ relay: DEFAULT_RELAY_URL, identity: identity() }),
    (err) => {
      assert.ok(err instanceof KxcoChainError)
      assert.equal(err.code, 'LICENCE_REQUIRED')
      assert.match(err.message, /Set KXCO_LICENCE_KEY/)
      return true
    },
  )
})

test('a loopback relay needs no licence, so local development is unaffected', async (t) => {
  const server = await relay()
  t.after(() => server.close())

  const chain = new KxcoChain({ relay: server.url, identity: identity() })
  assert.equal(chain.licensed, false)
  assert.equal((await chain.anchorHash({ hash: 'a'.repeat(64) })).chainId, CHAIN_ID)
})

test('requireLicence overrides the loopback heuristic in both directions', async (t) => {
  const server = await relay()
  t.after(() => server.close())

  assert.throws(
    () => new KxcoChain({ relay: server.url, identity: identity(), requireLicence: true }),
    (e) => e.code === 'LICENCE_REQUIRED',
  )
  assert.doesNotThrow(
    () => new KxcoChain({ relay: DEFAULT_RELAY_URL, identity: identity(), requireLicence: false }),
  )
})

test('the licence is sent as a bearer token by default', async (t) => {
  const server = await relay()
  t.after(() => server.close())

  const chain = new KxcoChain({ relay: server.url, identity: identity(), licenceKey: LICENCE })
  assert.equal(chain.licensed, true)
  await chain.anchorHash({ hash: 'a'.repeat(64) })
  assert.equal(server.last().headers.authorization, `Bearer ${LICENCE}`)
  assert.equal(server.last().headers['x-kxco-licence'], undefined)
})

// Some deployments sit behind a proxy that consumes Authorization for its own
// auth. The licence has to be able to travel in a header the proxy passes on.
test('the licence can travel in X-KXCO-Licence instead', async (t) => {
  const server = await relay()
  t.after(() => server.close())

  const chain = new KxcoChain({
    relay: server.url, identity: identity(), licenceKey: LICENCE, licenceHeader: 'x-kxco-licence',
  })
  await chain.anchorHash({ hash: 'a'.repeat(64) })
  assert.equal(server.last().headers['x-kxco-licence'], LICENCE)
  assert.equal(server.last().headers.authorization, undefined)
})

test('an unknown licence header name is refused at construction', () => {
  assert.throws(
    () => new KxcoChain({ relay: 'http://localhost', identity: identity(), licenceHeader: 'x-secret' }),
    /must be 'authorization' or 'x-kxco-licence'/,
  )
})

test('the licence key is read from the environment when not passed', () => {
  const before = process.env.KXCO_LICENCE_KEY
  process.env.KXCO_LICENCE_KEY = LICENCE
  try {
    const chain = new KxcoChain({ relay: DEFAULT_RELAY_URL, identity: identity() })
    assert.equal(chain.licensed, true)
  } finally {
    if (before === undefined) delete process.env.KXCO_LICENCE_KEY
    else process.env.KXCO_LICENCE_KEY = before
  }
})

test('a 401 or 403 from the relay is reported as a licence rejection', async (t) => {
  for (const status of [401, 403]) {
    const server = await relay(() => status)
    t.after(() => server.close())

    const chain = new KxcoChain({ relay: server.url, identity: identity(), licenceKey: LICENCE })
    await assert.rejects(
      () => chain.anchorHash({ hash: 'a'.repeat(64) }),
      (e) => e.code === 'LICENCE_REJECTED' && e.status === status,
      String(status),
    )
  }
})

// ── the chain-id assertion ──────────────────────────────────────────────────

test('every result names Armature L1', async (t) => {
  const server = await relay()
  t.after(() => server.close())

  const chain = new KxcoChain({ relay: server.url, identity: identity() })
  const result = await chain.anchorHash({ hash: 'a'.repeat(64) })
  assert.deepEqual(Object.keys(result).sort(), ['blockNumber', 'chainId', 'chainIdConfirmed', 'txHash'])
  assert.equal(result.chainId, 1111111)
})

// Returning this hash to a caller who is about to store it as proof would be
// worse than failing.
test('a response naming another chain throws', async (t) => {
  const server = await relay(() => ({ ok: true, txHash: '0x' + 'cd'.repeat(32), blockNumber: 9, chainId: 1 }))
  t.after(() => server.close())

  const chain = new KxcoChain({ relay: server.url, identity: identity() })
  await assert.rejects(
    () => chain.anchorHash({ hash: 'a'.repeat(64) }),
    (e) => e.code === 'WRONG_CHAIN' && /expected 1111111/.test(e.message),
  )
})

test('a response with no chain id throws, and says how to opt out', async (t) => {
  const server = await relay(() => ({ ok: true, txHash: '0x' + 'ef'.repeat(32), blockNumber: 9 }))
  t.after(() => server.close())

  const chain = new KxcoChain({ relay: server.url, identity: identity() })
  await assert.rejects(
    () => chain.anchorHash({ hash: 'a'.repeat(64) }),
    (e) => e.code === 'MISSING_CHAIN_ID' && /strictChainId: false/.test(e.message),
  )
})

test('strictChainId: false accepts a relay that predates the field', async (t) => {
  const server = await relay(() => ({ ok: true, txHash: '0x' + 'ef'.repeat(32), blockNumber: 9 }))
  t.after(() => server.close())

  const chain = new KxcoChain({ relay: server.url, identity: identity(), strictChainId: false })
  assert.equal((await chain.anchorHash({ hash: 'a'.repeat(64) })).chainId, CHAIN_ID)
})

// ── the intents added in 2.0.0 ──────────────────────────────────────────────

test('revokeKid sends its own operation', async (t) => {
  const server = await relay()
  t.after(() => server.close())

  const chain = new KxcoChain({ relay: server.url, identity: identity() })
  await chain.revokeKid({ kid: 'aa29f37ab7f4b2cf', reason: 'compromised' })
  assert.equal(server.last().intent.operation, 'revokeKid')
  assert.equal(server.last().intent.payload.kid, 'aa29f37ab7f4b2cf')
  assert.equal(server.last().intent.payload.reason, 'compromised')
})

test('anchorHash takes any digest and rejects anything that is not one', async (t) => {
  const server = await relay()
  t.after(() => server.close())

  const chain = new KxcoChain({ relay: server.url, identity: identity() })
  await chain.anchorHash({ hash: 'f'.repeat(64), purpose: 'quarterly-report' })
  assert.equal(server.last().intent.operation, 'anchorHash')
  assert.equal(server.last().intent.payload.purpose, 'quarterly-report')

  for (const hash of ['deadbeef', '', 'g'.repeat(64), undefined]) {
    await assert.rejects(() => chain.anchorHash({ hash }), (e) => e.code === 'BAD_ARGUMENT', String(hash))
  }
})

// Aliases, not new wire operations: the relay sees the name it always has.
test('registerIdentity and registerAgent are names over existing wire operations', async (t) => {
  const server = await relay()
  t.after(() => server.close())

  const chain = new KxcoChain({ relay: server.url, identity: identity() })

  await chain.registerIdentity({ publicKeyHex: 'ab'.repeat(1952) })
  assert.equal(server.last().intent.operation, 'registerInstitution')

  await chain.registerAgent({
    agentKid: 'bb29f37ab7f4b2cf', agentPublicKeyHex: 'cd'.repeat(1952),
    agentType: 'llm', scopeHash: 'a'.repeat(64), expiresAt: 1900000000,
  })
  assert.equal(server.last().intent.operation, 'issueAgentCredential')
})

// ── metering ────────────────────────────────────────────────────────────────

test('usage events carry the operation and never the whole licence', async (t) => {
  const server = await relay()
  t.after(() => server.close())

  const events = []
  const chain = new KxcoChain({
    relay: server.url, identity: identity(), licenceKey: LICENCE, onUsageEvent: (e) => events.push(e),
  })
  await chain.revokeKid({ kid: 'aa29f37ab7f4b2cf' })

  assert.equal(events.length, 1)
  assert.equal(events[0].event, 'relay_post')
  assert.equal(events[0].operation, 'revokeKid')
  assert.equal(events[0].kid, 'aa29f37ab7f4b2cf')
  assert.equal(events[0].chainId, CHAIN_ID)
  assert.equal(events[0].licencePrefix, 'kxco_liv')
  assert.ok(!JSON.stringify(events[0]).includes(LICENCE), 'the full licence must never reach a log line')
})

// A library writing to a caller's logs uninvited is a bug, not a feature.
test('no usage events are emitted unless a sink is given', async (t) => {
  const server = await relay()
  t.after(() => server.close())

  const chain = new KxcoChain({ relay: server.url, identity: identity() })
  await assert.doesNotReject(() => chain.anchorHash({ hash: 'a'.repeat(64) }))
})

// ── no wallet, no gas ───────────────────────────────────────────────────────

// The commercial promise: an institution never holds ARMR and never sets a gas
// price. If either ever leaked into an intent, this would catch it.
test('no intent ever carries a gas price, a wallet or a private key', async (t) => {
  const server = await relay()
  t.after(() => server.close())

  const chain = new KxcoChain({ relay: server.url, identity: identity() })
  await chain.registerIdentity({ publicKeyHex: 'ab'.repeat(1952) })
  await chain.anchorHash({ hash: 'a'.repeat(64) })
  await chain.revokeKid({ kid: 'aa29f37ab7f4b2cf' })

  for (const { intent } of server.seen) {
    const body = JSON.stringify(intent).toLowerCase()
    for (const forbidden of ['gasprice', 'gaslimit', 'privatekey', 'mnemonic', 'armr', 'wallet', 'from"']) {
      assert.ok(!body.includes(forbidden), `${intent.operation} must not carry ${forbidden}`)
    }
    assert.deepEqual(
      Object.keys(intent).sort(),
      ['institutionKid', 'nonce', 'operation', 'payload', 'signature', 'timestamp'],
    )
  }
})

// ── the relay's answer is not taken on trust ────────────────────────────────

// Without this, `strictChainId: false` returned chainId 1111111 on a response
// that never mentioned a chain — inventing the one fact the caller is about to
// store as proof.
test('a skipped chain-id check is reported as skipped, not answered', async (t) => {
  const withId = await relay()
  const withoutId = await relay(() => ({ ok: true, txHash: '0x' + 'ef'.repeat(32), blockNumber: 9 }))
  t.after(() => Promise.all([withId.close(), withoutId.close()]))

  const confirmed = await new KxcoChain({ relay: withId.url, identity: identity() })
    .anchorHash({ hash: 'a'.repeat(64) })
  assert.equal(confirmed.chainId, CHAIN_ID)
  assert.equal(confirmed.chainIdConfirmed, true)

  const unconfirmed = await new KxcoChain({
    relay: withoutId.url, identity: identity(), strictChainId: false,
  }).anchorHash({ hash: 'a'.repeat(64) })
  assert.equal(unconfirmed.chainId, CHAIN_ID)
  assert.equal(unconfirmed.chainIdConfirmed, false, 'the relay never said, so this must not claim it did')
})

// A malformed hash left unchecked travels into an envelope and reappears much
// later as "this envelope is not anchored", blaming the wrong component.
test('a malformed txHash or blockNumber is blamed on the relay, at the relay', async (t) => {
  const cases = [
    ['txHash', { ok: true, txHash: '0xdeadbeef', blockNumber: 1, chainId: CHAIN_ID }],
    ['txHash null', { ok: true, txHash: null, blockNumber: 1, chainId: CHAIN_ID }],
    ['no 0x', { ok: true, txHash: 'ab'.repeat(32), blockNumber: 1, chainId: CHAIN_ID }],
    ['blockNumber', { ok: true, txHash: '0x' + 'ab'.repeat(32), blockNumber: 'soon', chainId: CHAIN_ID }],
  ]
  for (const [label, body] of cases) {
    const server = await relay(() => body)
    t.after(() => server.close())
    const chain = new KxcoChain({ relay: server.url, identity: identity() })
    await assert.rejects(
      () => chain.anchorHash({ hash: 'a'.repeat(64) }),
      (e) => e.code === 'BAD_RELAY_RESPONSE' && /relay returned a malformed/.test(e.message),
      label,
    )
  }
})
