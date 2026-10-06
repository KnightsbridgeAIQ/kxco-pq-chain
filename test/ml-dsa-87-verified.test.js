/**
 * ML-DSA-87 on the on-chain verified path.
 *
 * PQVerifyingRelayV2 verifies ML-DSA-87 as well as ML-DSA-65, and the key's
 * length decides which. Tested here:
 *
 *   - an ML-DSA-87 message is the ML-DSA-65 message with keccak256("ML-DSA-87")
 *     as a sixth prefix word, after the nonce, and an ML-DSA-65 message is
 *     byte for byte what it was
 *   - a rotation names an ML-DSA-87 NEW key in its arguments, and only then
 *   - signIntentV2 signs with the set the key belongs to, over the message
 *     that names it, and refuses a key of neither length
 *   - KxcoChain sends an ML-DSA-87 identity to /intents/v2 where the relay
 *     lists ML-DSA-87, and an ML-DSA-65 identity exactly as before
 *
 * kxco-verified-contracts' EndToEndPQ87.test.js checks the same encoder
 * against the contract's own `authorisingMessageFor`.
 */

import { createServer } from 'node:http'
import { randomBytes } from 'node:crypto'
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { mlDsa, mlDsa87, fingerprint } from 'kxco-post-quantum'
import {
  KxcoChain, authorisingMessage, signIntentV2, abiEncode,
  INTENT_V2_ARGS, OPERATION_TAGS, ALGORITHM_TAGS,
} from '../src/index.js'
import { toV2 } from '../src/v2-payload.js'

const VERIFIER = '0xB94E0829046B7c50db51C5eC4F6F4C8B3d7fb2F5'
const CHAIN_ID = 1111111
const KID = 'aa29f37ab7f4b2cf'

// Computed independently with ethers.id(), not with this package's keccak.
const TAG65 = '0xab8a1c99e5fb2c095e053ef39623afdab90d4ba4e38867125aa2705b959f6500'
const TAG87 = '0xe1a4e7401908d7cbe8cd2a7e538c3570edd54c447ba6eba866ac8dd622923831'

const k87 = mlDsa87.keypairFromMaster(randomBytes(32))
const k65 = mlDsa.keypairFromMaster(randomBytes(32))
const hex = (b) => Buffer.from(b).toString('hex')

const base = {
  relayAddress: VERIFIER, operationTag: OPERATION_TAGS.anchorAuditRoot, kid: KID, nonce: 9,
  args: INTENT_V2_ARGS.anchorAuditRoot('0x' + 'ab'.repeat(32), 4096), chainId: CHAIN_ID,
}

// ── the bytes ───────────────────────────────────────────────────────────────

test('the algorithm tags are keccak256 of the set names', () => {
  assert.equal(ALGORITHM_TAGS['ML-DSA-65'], TAG65)
  assert.equal(ALGORITHM_TAGS['ML-DSA-87'], TAG87)
})

test('an ML-DSA-87 message is the ML-DSA-65 prefix with the ML-DSA-87 tag after the nonce', () => {
  const m65 = authorisingMessage(base)
  const m87 = authorisingMessage({ ...base, alg: 'ML-DSA-87' })
  // Five prefix words, then the tag, then the same arguments.
  assert.equal(m87.length, m65.length + 32)
  assert.equal(hex(m87.subarray(0, 160)), hex(m65.subarray(0, 160)))
  assert.equal('0x' + hex(m87.subarray(160, 192)), TAG87)
  assert.equal(hex(m87.subarray(192)), hex(m65.subarray(160)))
})

test('an ML-DSA-65 message is unchanged whether alg is omitted or stated', () => {
  const prefix = abiEncode([
    { type: 'address', value: VERIFIER }, { type: 'uint256', value: CHAIN_ID },
    { type: 'bytes32', value: OPERATION_TAGS.anchorAuditRoot }, { type: 'bytes8', value: '0x' + KID },
    { type: 'uint64', value: 9 },
  ])
  const expected = hex(prefix) + hex(abiEncode(base.args))
  assert.equal(hex(authorisingMessage(base)), expected)
  assert.equal(hex(authorisingMessage({ ...base, alg: 'ML-DSA-65' })), expected)
})

test('an algorithm outside the two sets is refused', () => {
  for (const alg of ['ML-DSA-44', 'ml-dsa-87', '', null, 87]) {
    assert.throws(() => authorisingMessage({ ...base, alg }), TypeError, JSON.stringify(alg))
  }
})

test('a rotation names an ML-DSA-87 new key in its arguments, and only then', () => {
  const h = '0x' + '77'.repeat(32)
  const plain = hex(abiEncode(INTENT_V2_ARGS.rotateInstitutionKey('bb29f37ab7f4b2cf', h)))
  assert.equal(hex(abiEncode(INTENT_V2_ARGS.rotateInstitutionKey('bb29f37ab7f4b2cf', h, 'ML-DSA-65'))), plain)
  assert.equal(hex(abiEncode(INTENT_V2_ARGS.rotateInstitutionKey('bb29f37ab7f4b2cf', h, 'ML-DSA-87'))),
    plain + TAG87.slice(2))

  // toV2 reads the new key's set from its length.
  const to87 = toV2('rotateKey', { newKid: 'bb29f37ab7f4b2cf', newPublicKeyHex: hex(k87.publicKey) })
  const to65 = toV2('rotateKey', { newKid: 'bb29f37ab7f4b2cf', newPublicKeyHex: hex(k65.publicKey) })
  assert.equal(to87.args.length, 3)
  assert.equal(to87.args[2].value, TAG87)
  assert.equal(to65.args.length, 2)
})

test('a key that is only hashed is never named: issuing a credential to an ML-DSA-87 key', () => {
  const mapped = toV2('issueCredential', { userKid: 'cc29f37ab7f4b2cf', userPublicKeyHex: hex(k87.publicKey), role: 'r' })
  assert.equal(mapped.args.length, 4)
  assert.ok(mapped.args.every((a) => a.value !== TAG87))
})

// ── signing ─────────────────────────────────────────────────────────────────

test('signIntentV2 signs ML-DSA-87 over the message that names it, and not over the other', () => {
  const s = signIntentV2({ keypair: k87, ...base, kid: undefined })
  assert.equal(s.alg, 'ML-DSA-87')
  assert.equal(s.kid, fingerprint(k87.publicKey))
  assert.equal(s.signature.length, 4627 * 2)
  const named = authorisingMessage({ ...base, kid: s.kid, alg: 'ML-DSA-87' })
  const unnamed = authorisingMessage({ ...base, kid: s.kid })
  assert.equal(hex(s.message), hex(named))
  assert.equal(mlDsa87.verify(k87.publicKey, named, s.signature), true)
  assert.equal(mlDsa87.verify(k87.publicKey, unnamed, s.signature), false)
})

test('signIntentV2 is unchanged for ML-DSA-65', () => {
  const s = signIntentV2({ keypair: k65, ...base, kid: undefined })
  assert.equal(s.alg, 'ML-DSA-65')
  assert.equal(s.signature.length, 3309 * 2)
  const msg = authorisingMessage({ ...base, kid: s.kid })
  assert.equal(hex(s.message), hex(msg))
  assert.equal(mlDsa.verify(k65.publicKey, msg, s.signature), true)
})

test('signIntentV2 refuses a key of neither length', () => {
  const bad = { publicKey: new Uint8Array(2000), secretKey: k87.secretKey }
  assert.throws(() => signIntentV2({ keypair: bad, ...base }), /neither ML-DSA-65/)
})

// ── the client ──────────────────────────────────────────────────────────────

function identityFor(kp, mod) {
  return {
    kid: fingerprint(kp.publicKey),
    publicKey: kp.publicKey,
    sign: async (message) => Buffer.from(mod.sign(kp.secretKey, message), 'hex'),
  }
}

/** A relay whose verifier lists the given algorithms. */
async function relay(algorithms, nonce = 4) {
  const seen = []
  const server = createServer(async (req, res) => {
    const json = (status, body) => {
      res.writeHead(status, { 'content-type': 'application/json' })
      res.end(JSON.stringify(body))
    }
    if (req.method === 'GET' && req.url === '/intents/v2/params') {
      return json(200, { ok: true, verifyingRelay: VERIFIER, chainId: CHAIN_ID, algorithms })
    }
    if (req.method === 'GET' && req.url.startsWith('/intents/v2/nonce/')) {
      return json(200, { ok: true, kid: req.url.split('/').pop(), nonce })
    }
    let body = ''
    for await (const chunk of req) body += chunk
    seen.push({ path: req.url, intent: JSON.parse(body) })
    json(200, { ok: true, txHash: '0x' + 'ab'.repeat(32), blockNumber: 9, chainId: CHAIN_ID })
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  return {
    url: `http://127.0.0.1:${server.address().port}`,
    last: () => seen.at(-1),
    close: () => new Promise((r) => server.close(r)),
  }
}

test('an ML-DSA-87 client takes the verified path where the relay lists ML-DSA-87', async () => {
  const r = await relay(['ML-DSA-65', 'ML-DSA-87'], 4)
  try {
    const id87 = identityFor(k87, mlDsa87)
    const payload = { rootHash: 'cd'.repeat(32), entryCount: 12 }
    await new KxcoChain({ relay: r.url, identity: id87 }).anchorAuditRoot(payload)

    const { path, intent } = r.last()
    assert.equal(path, '/intents/v2')
    assert.equal(intent.alg, 'ML-DSA-87')
    assert.equal(intent.publicKeyHex, hex(k87.publicKey))
    assert.equal(intent.nonce, 4, 'the nonce comes from the chain')

    const msg = (alg) => authorisingMessage({
      relayAddress: VERIFIER, operationTag: OPERATION_TAGS.anchorAuditRoot, kid: id87.kid,
      nonce: 4, args: toV2('anchorAuditRoot', payload).args, chainId: CHAIN_ID, alg,
    })
    assert.equal(mlDsa87.verify(k87.publicKey, msg('ML-DSA-87'), intent.signature), true,
      'the signature must cover the message PQVerifyingRelayV2 builds for an ML-DSA-87 key')
    assert.equal(mlDsa87.verify(k87.publicKey, msg(undefined), intent.signature), false,
      'and must not cover the ML-DSA-65 form')
  } finally { await r.close() }
})

test('an ML-DSA-65 client on that same relay sends exactly what it sent before', async () => {
  const r = await relay(['ML-DSA-65', 'ML-DSA-87'], 4)
  try {
    const id65 = identityFor(k65, mlDsa)
    const payload = { rootHash: 'cd'.repeat(32), entryCount: 12 }
    await new KxcoChain({ relay: r.url, identity: id65 }).anchorAuditRoot(payload)

    const { path, intent } = r.last()
    assert.equal(path, '/intents/v2')
    assert.equal('alg' in intent, false, 'no new field on an ML-DSA-65 intent')
    const msg = authorisingMessage({
      relayAddress: VERIFIER, operationTag: OPERATION_TAGS.anchorAuditRoot, kid: id65.kid,
      nonce: 4, args: toV2('anchorAuditRoot', payload).args, chainId: CHAIN_ID,
    })
    assert.equal(mlDsa.verify(k65.publicKey, msg, intent.signature), true)
  } finally { await r.close() }
})

test('a relay that lists ML-DSA-65 alone keeps an ML-DSA-87 client on v1.1', async () => {
  const r = await relay(['ML-DSA-65'])
  try {
    await new KxcoChain({ relay: r.url, identity: identityFor(k87, mlDsa87) })
      .anchorAuditRoot({ rootHash: 'cd'.repeat(32), entryCount: 1 })
    assert.equal(r.last().path, '/intents')
    assert.equal(r.last().intent.alg, 'ML-DSA-87')
    assert.ok(r.last().intent.timestamp, 'a v1.1 intent')
  } finally { await r.close() }
})

// ── rotation: both keys sign the one message ────────────────────────────────

const k87next = mlDsa87.keypairFromMaster(randomBytes(32))

/** A relay that offers the verified path, and one that does not. */
async function relayFor(verified) {
  if (verified) return relay(['ML-DSA-65', 'ML-DSA-87'], 6)
  const seen = []
  const server = createServer(async (req, res) => {
    const json = (status, body) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)) }
    if (req.method === 'GET') return json(503, { ok: false, code: 'VERIFIED_PATH_UNAVAILABLE' })
    let body = ''
    for await (const chunk of req) body += chunk
    seen.push({ path: req.url, intent: JSON.parse(body) })
    json(200, { ok: true, txHash: '0x' + 'ab'.repeat(32), blockNumber: 9, chainId: CHAIN_ID })
  })
  await new Promise((r) => server.listen(0, '127.0.0.1', r))
  return { url: `http://127.0.0.1:${server.address().port}`, last: () => seen.at(-1), close: () => new Promise((r) => server.close(r)) }
}

function rotationMessage(oldId, oldAlg, newKp, nonce) {
  const newHex = hex(newKp.publicKey)
  return authorisingMessage({
    relayAddress: VERIFIER, operationTag: OPERATION_TAGS.rotateInstitutionKey, kid: oldId.kid, nonce,
    args: INTENT_V2_ARGS.rotateInstitutionKey(fingerprint(newKp.publicKey), toV2('rotateKey',
      { newKid: fingerprint(newKp.publicKey), newPublicKeyHex: newHex }).args[1].value, 'ML-DSA-87'),
    chainId: CHAIN_ID, alg: oldAlg,
  })
}

test('an ML-DSA-65 institution rotates to ML-DSA-87 on the verified path: both keys sign the same bytes', async () => {
  const r = await relayFor(true)
  try {
    const old = identityFor(k65, mlDsa)
    const next = identityFor(k87next, mlDsa87)
    await new KxcoChain({ relay: r.url, identity: old })
      .rotateKey({ newKid: next.kid, newPublicKeyHex: hex(k87next.publicKey), newIdentity: next })

    const { path, intent } = r.last()
    assert.equal(path, '/intents/v2')
    assert.equal('alg' in intent, false, 'the old key is ML-DSA-65, so the intent names no set')
    assert.equal(intent.payload.newKid, next.kid)
    assert.equal(intent.payload.newSignature.length, 4627 * 2)

    // Old-key prefix (no tag), and the ML-DSA-87 tag at the end of the arguments.
    const msg = rotationMessage(old, undefined, k87next, 6)
    assert.equal('0x' + hex(msg.subarray(msg.length - 32)), TAG87)
    assert.equal(mlDsa.verify(k65.publicKey, msg, intent.signature), true, 'old key over the rotation bytes')
    assert.equal(mlDsa87.verify(k87next.publicKey, msg, intent.payload.newSignature), true, 'new key over the SAME bytes')
  } finally { await r.close() }
})

test('an ML-DSA-87 institution rotates to another ML-DSA-87 key: the prefix names ML-DSA-87 as well', async () => {
  const r = await relayFor(true)
  try {
    const old = identityFor(k87, mlDsa87)
    const next = identityFor(k87next, mlDsa87)
    await new KxcoChain({ relay: r.url, identity: old })
      .rotateKey({ newKid: next.kid, newPublicKeyHex: hex(k87next.publicKey), newIdentity: next })
    const { intent } = r.last()
    const msg = rotationMessage(old, 'ML-DSA-87', k87next, 6)
    assert.equal(intent.alg, 'ML-DSA-87')
    assert.equal(mlDsa87.verify(k87.publicKey, msg, intent.signature), true)
    assert.equal(mlDsa87.verify(k87next.publicKey, msg, intent.payload.newSignature), true)
  } finally { await r.close() }
})

test('on the verified path a rotation without the new key, or with the wrong one, is refused before sending', async () => {
  const r = await relayFor(true)
  try {
    const client = new KxcoChain({ relay: r.url, identity: identityFor(k65, mlDsa) })
    const base = { newKid: fingerprint(k87next.publicKey), newPublicKeyHex: hex(k87next.publicKey) }
    await assert.rejects(() => client.rotateKey(base), (e) => e.code === 'NEW_KEY_SIGNER_REQUIRED')
    await assert.rejects(() => client.rotateKey({ ...base, newIdentity: identityFor(k87, mlDsa87) }),
      (e) => e.code === 'BAD_ARGUMENT' && /different key/.test(e.message))
    // A signer that does not expose its key, signing with the other set.
    const wrongSet = { sign: async (m) => Buffer.from(mlDsa.sign(k65.secretKey, m), 'hex') }
    await assert.rejects(() => client.rotateKey({ ...base, newIdentity: wrongSet }),
      (e) => e.code === 'BAD_ARGUMENT' && /ML-DSA-87/.test(e.message))
    assert.equal(r.last(), undefined, 'nothing was sent')
  } finally { await r.close() }
})

test('a v1 rotation is unchanged: no new-key signature, no new field', async () => {
  const r = await relayFor(false)
  try {
    await new KxcoChain({ relay: r.url, identity: identityFor(k65, mlDsa) })
      .rotateKey({ newKid: fingerprint(k87next.publicKey), newPublicKeyHex: hex(k87next.publicKey) })
    assert.equal(r.last().path, '/intents')
    assert.deepEqual(Object.keys(r.last().intent.payload).sort(), ['newKid', 'newPublicKeyHex'])
  } finally { await r.close() }
})
