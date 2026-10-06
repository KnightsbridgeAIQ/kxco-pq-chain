/**
 * ML-DSA-87 intents.
 *
 * Four properties, each tested in both directions:
 *
 *   1. The algorithm is inside the signed bytes. A v1.1 intent names it on its
 *      own line, so it cannot be changed without breaking the signature.
 *   2. ML-DSA-65 is untouched. With no algorithm stated, the message is the v1
 *      message byte for byte, and an ML-DSA-65 client sends exactly what it
 *      sent before, down the same path.
 *   3. The key decides. A client whose key is ML-DSA-87 signs ML-DSA-87, and a
 *      stated algorithm that disagrees with the key is refused.
 *   4. An ML-DSA-87 intent reaches the on-chain verified path only where the
 *      relay lists ML-DSA-87 among the algorithms its verifier checks. Where it
 *      does not, the relay verifies ML-DSA-87 off-chain. The verified path
 *      itself is tested in ml-dsa-87-verified.test.js.
 */

import { createServer } from 'node:http'
import { randomBytes } from 'node:crypto'
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { mlDsa, mlDsa87, fingerprint } from 'kxco-post-quantum'
import {
  KxcoChain, KxcoChainError,
  buildSigningMessage, buildIntent, algForPublicKey, INTENT_ALGS,
} from '../src/index.js'

const k87 = mlDsa87.keypairFromMaster(randomBytes(32))
const k65 = mlDsa.keypairFromMaster(randomBytes(32))

function identityFor(kp, mod) {
  return {
    kid: fingerprint(kp.publicKey),
    publicKey: kp.publicKey,
    sign: async (message) => Buffer.from(mod.sign(kp.secretKey, message), 'hex'),
  }
}
const id87 = identityFor(k87, mlDsa87)
const id65 = identityFor(k65, mlDsa)

const ARGS = ['anchorHash', 'aa29f37ab7f4b2cf', 'ab'.repeat(32), 1700000000, { hash: 'cd'.repeat(32), purpose: 'q3' }]
const text = (bytes) => Buffer.from(bytes).toString('utf8')

// ── the message ─────────────────────────────────────────────────────────────

test('with no algorithm the message is v1, byte for byte', () => {
  const v1 = [
    'kxco-relay-v1',
    'operation: anchorHash',
    'institutionKid: aa29f37ab7f4b2cf',
    `nonce: ${'ab'.repeat(32)}`,
    'timestamp: 1700000000',
    `payload: {"hash":"${'cd'.repeat(32)}","purpose":"q3"}`,
  ].join('\n')
  assert.equal(text(buildSigningMessage(...ARGS)), v1)
  assert.equal(text(buildSigningMessage(...ARGS, undefined)), v1)
})

test('v1.1 names the algorithm inside the signed bytes, under its own first line', () => {
  assert.equal(text(buildSigningMessage(...ARGS, 'ML-DSA-87')), [
    'kxco-relay-v1.1',
    'alg: ML-DSA-87',
    'operation: anchorHash',
    'institutionKid: aa29f37ab7f4b2cf',
    `nonce: ${'ab'.repeat(32)}`,
    'timestamp: 1700000000',
    `payload: {"hash":"${'cd'.repeat(32)}","purpose":"q3"}`,
  ].join('\n'))
  // Stating ML-DSA-65 is v1.1 too, and differs from v1: the two cannot collide.
  const v11for65 = text(buildSigningMessage(...ARGS, 'ML-DSA-65'))
  assert.ok(v11for65.startsWith('kxco-relay-v1.1\nalg: ML-DSA-65\n'))
  assert.notEqual(v11for65, text(buildSigningMessage(...ARGS)))
})

test('an algorithm outside the two sets is refused before anything is built', () => {
  assert.deepEqual([...INTENT_ALGS], ['ML-DSA-65', 'ML-DSA-87'])
  for (const bad of ['ML-DSA-44', 'ml-dsa-87', 'ML-DSA-87\n', 'ML-DSA-87 ', '', null, 87, 'SLH-DSA-SHA2-128s']) {
    assert.throws(
      () => buildSigningMessage(...ARGS, bad),
      (err) => err instanceof KxcoChainError && err.code === 'BAD_ARGUMENT',
      JSON.stringify(bad),
    )
  }
})

test('the key length decides the parameter set, and any other length is refused', () => {
  assert.equal(algForPublicKey(k65.publicKey), 'ML-DSA-65')
  assert.equal(algForPublicKey(k87.publicKey), 'ML-DSA-87')
  assert.equal(algForPublicKey(Buffer.from(k87.publicKey).toString('hex')), 'ML-DSA-87')
  assert.equal(algForPublicKey('0x' + Buffer.from(k65.publicKey).toString('hex')), 'ML-DSA-65')
  for (const n of [0, 1312, 1951, 1953, 2591, 2593, 4896]) {
    assert.throws(() => algForPublicKey(new Uint8Array(n)),
      (err) => err instanceof KxcoChainError && err.code === 'BAD_ARGUMENT', `${n} bytes`)
  }
})

// ── signing ─────────────────────────────────────────────────────────────────

test('an ML-DSA-87 intent signs and verifies, and its algorithm is bound to the signature', async () => {
  const intent = await buildIntent({
    operation: 'anchorHash', institutionKid: id87.kid,
    payload: { hash: 'ef'.repeat(32), purpose: 'p' }, identity: id87, alg: 'ML-DSA-87',
  })
  assert.equal(intent.alg, 'ML-DSA-87')
  assert.equal(intent.signature.length, 4627 * 2, 'an ML-DSA-87 signature is 4627 bytes')

  const { operation, institutionKid, nonce, timestamp, payload, signature } = intent
  const msg = buildSigningMessage(operation, institutionKid, nonce, timestamp, payload, 'ML-DSA-87')
  assert.equal(mlDsa87.verify(k87.publicKey, msg, signature), true)

  // Restating the intent as ML-DSA-65, or as v1, changes the signed bytes.
  const as65 = buildSigningMessage(operation, institutionKid, nonce, timestamp, payload, 'ML-DSA-65')
  const asV1 = buildSigningMessage(operation, institutionKid, nonce, timestamp, payload)
  assert.equal(mlDsa87.verify(k87.publicKey, as65, signature), false)
  assert.equal(mlDsa87.verify(k87.publicKey, asV1, signature), false)
})

test('cross-set: an ML-DSA-87 signature or key is refused by the ML-DSA-65 verifier, and the reverse', async () => {
  const msg = buildSigningMessage(...ARGS, 'ML-DSA-87')
  const sig87 = mlDsa87.sign(k87.secretKey, msg)
  assert.equal(mlDsa.verify(k87.publicKey, msg, sig87), false)

  const sig65 = mlDsa.sign(k65.secretKey, msg)
  assert.equal(mlDsa87.verify(k65.publicKey, msg, sig65), false)
  assert.equal(mlDsa87.verify(k87.publicKey, msg, sig65), false)
})

test('an ML-DSA-65 intent with no algorithm is a v1 intent, with no new field', async () => {
  const intent = await buildIntent({
    operation: 'anchorHash', institutionKid: id65.kid, payload: { hash: 'ef'.repeat(32) }, identity: id65,
  })
  assert.equal('alg' in intent, false)
  const { operation, institutionKid, nonce, timestamp, payload, signature } = intent
  assert.equal(mlDsa.verify(k65.publicKey,
    buildSigningMessage(operation, institutionKid, nonce, timestamp, payload), signature), true)
})

// ── the client ──────────────────────────────────────────────────────────────

const VERIFIER = '0xB94E0829046B7c50db51C5eC4F6F4C8B3d7fb2F5'

/** A relay that offers the on-chain verified path. */
async function verifyingRelay() {
  const seen = []
  let probes = 0
  const server = createServer(async (req, res) => {
    const json = (status, body) => {
      res.writeHead(status, { 'content-type': 'application/json' })
      res.end(JSON.stringify(body))
    }
    if (req.method === 'GET' && req.url === '/intents/v2/params') {
      probes++
      return json(200, { ok: true, verifyingRelay: VERIFIER, chainId: 1111111 })
    }
    if (req.method === 'GET' && req.url.startsWith('/intents/v2/nonce/')) {
      return json(200, { ok: true, kid: req.url.split('/').pop(), nonce: 1 })
    }
    let body = ''
    for await (const chunk of req) body += chunk
    seen.push({ path: req.url, intent: JSON.parse(body) })
    json(200, { ok: true, txHash: '0x' + 'ab'.repeat(32), blockNumber: 9, chainId: 1111111 })
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    last: () => seen.at(-1), get probes() { return probes },
    close: () => new Promise((r) => server.close(r)),
  }
}

test('an ML-DSA-87 client stays on v1.1 where the verified path does not list ML-DSA-87', async () => {
  // This relay's params name no algorithms, which means ML-DSA-65 only: the
  // verifier is PQVerifyingRelay, or ML-DSA-87 is not active on the chain yet.
  const r = await verifyingRelay()
  try {
    const client = new KxcoChain({ relay: r.url, identity: id87 })
    assert.equal(client.alg, 'ML-DSA-87')
    await client.anchorAuditRoot({ rootHash: 'ab'.repeat(32), entryCount: 7 })

    const { path, intent } = r.last()
    assert.equal(path, '/intents', 'an ML-DSA-87 intent must go to the relay-verified path')
    assert.equal(r.probes, 1, 'asked once, and the answer did not include ML-DSA-87')
    assert.equal(intent.alg, 'ML-DSA-87')
    const msg = buildSigningMessage(intent.operation, intent.institutionKid, intent.nonce,
      intent.timestamp, intent.payload, intent.alg)
    assert.equal(mlDsa87.verify(k87.publicKey, msg, intent.signature), true)
  } finally { await r.close() }
})

test('an ML-DSA-65 client still takes the verified path, and still sends no algorithm', async () => {
  const r = await verifyingRelay()
  try {
    const client = new KxcoChain({ relay: r.url, identity: id65 })
    assert.equal(client.alg, 'ML-DSA-65')
    await client.anchorAuditRoot({ rootHash: 'ab'.repeat(32), entryCount: 7 })
    assert.equal(r.last().path, '/intents/v2')
    assert.equal('alg' in r.last().intent, false)

    const v1 = new KxcoChain({ relay: r.url, identity: id65, verifiedPath: false })
    await v1.anchorAuditRoot({ rootHash: 'ab'.repeat(32), entryCount: 7 })
    assert.equal(r.last().path, '/intents')
    assert.equal('alg' in r.last().intent, false)
  } finally { await r.close() }
})

test('a stated algorithm that disagrees with the key is refused at construction', () => {
  const relay = 'http://127.0.0.1:1'
  const refused = (opts, label) => assert.throws(
    () => new KxcoChain({ relay, ...opts }),
    (err) => err instanceof KxcoChainError && err.code === 'BAD_CONFIG', label)

  refused({ identity: id87, alg: 'ML-DSA-65' }, 'an ML-DSA-87 key stated as ML-DSA-65')
  refused({ identity: id65, alg: 'ML-DSA-87' }, 'an ML-DSA-65 key stated as ML-DSA-87')
  refused({ identity: { ...id65, alg: 'ML-DSA-87' } }, 'identity.alg disagreeing with its key')
  refused({ identity: id65, alg: 'ML-DSA-44' }, 'a set this client does not sign')

  // With no key to read, the stated algorithm is used; with neither, ML-DSA-65.
  const keyless = { kid: id87.kid, sign: id87.sign }
  assert.equal(new KxcoChain({ relay, identity: keyless, alg: 'ML-DSA-87' }).alg, 'ML-DSA-87')
  assert.equal(new KxcoChain({ relay, identity: keyless }).alg, 'ML-DSA-65')
  assert.equal(new KxcoChain({ relay, identity: id87, alg: 'ML-DSA-87' }).alg, 'ML-DSA-87')
})
