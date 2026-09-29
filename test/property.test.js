// Property-based tests with fast-check.
//
// chain.test.js checks each operation against a mock relay with fixed inputs.
// These ask the general question about the pieces every write is built from:
// for ANY payload, is the canonical form the same whatever order its keys were
// written in; does the signing message bind every field, so changing any one
// changes the bytes; does a signed intent verify under the identity's key and
// fail once any field is changed; is every nonce fresh; and does the client
// refuse bad configuration with its own typed error? fast-check generates the
// inputs and, when a property breaks, shrinks the failing case to the smallest
// one that still breaks it, so a failure arrives as a minimal reproduction
// rather than a random blob.
//
// Nothing here touches the network. The identity is a local stand-in with the
// two members the client uses, `kid` and `sign()`, signing with
// kxco-post-quantum, and no relay is ever called. Runs on whichever
// kxco-post-quantum backend is live.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { isDeepStrictEqual } from 'node:util'
import fc from 'fast-check'
import { mlDsa, fingerprint } from 'kxco-post-quantum'
import {
  KxcoChain, KxcoChainError,
  buildIntent, buildSigningMessage, randomNonce, canonicalize,
} from '../src/index.js'

// Signing is milliseconds per case, so a modest run count keeps the suite fast
// while still covering a spread of operations and payloads.
const RUNS = { numRuns: 40 }

// One key for the run: the properties are about intents, not keys.
const KEY = mlDsa.keypairFromMaster(new Uint8Array(32).fill(9), 'kxco-pq-chain/property-tests/v1')
const IDENTITY = {
  kid: fingerprint(KEY.publicKey),
  publicKey: KEY.publicKey,
  async sign(message) {
    return Buffer.from(mlDsa.sign(KEY.secretKey, message), 'hex')
  },
}

// JSON values in the subset canonicalize accepts: null, booleans, integers,
// strings, arrays and objects. Objects are built with Object.fromEntries, so
// every key is an own property. Keys mix any Unicode, plain ASCII and
// integer-like names, which JavaScript enumerates ahead of the rest whatever
// order they were inserted in. `__proto__` is left out of the generated keys.
const key = fc.oneof(fc.string({ unit: 'binary', maxLength: 8 }), fc.string({ maxLength: 8 }), fc.nat(1000).map(String))
  .filter((k) => k !== '__proto__')
const { value: json } = fc.letrec((tie) => ({
  value: fc.oneof(
    { depthSize: 'small', withCrossShrink: true },
    fc.constant(null),
    fc.boolean(),
    fc.oneof(fc.integer(), fc.maxSafeInteger()),
    fc.string({ unit: 'binary', maxLength: 20 }),
    tie('array'),
    tie('object'),
  ),
  array: fc.array(tie('value'), { maxLength: 4 }),
  object: fc.uniqueArray(fc.tuple(key, tie('value')), { maxLength: 5, selector: ([k]) => k })
    .map((entries) => Object.fromEntries(entries)),
}))
const payload = fc.uniqueArray(fc.tuple(key, json), { maxLength: 6, selector: ([k]) => k })
  .map((entries) => Object.fromEntries(entries))

// The same value with every object's keys inserted in a different order.
function reorder(v, turn) {
  if (Array.isArray(v)) return v.map((x) => reorder(x, turn))
  if (v === null || typeof v !== 'object') return v
  const entries = Object.entries(v).map(([k, x]) => [k, reorder(x, turn)])
  const n = entries.length
  const rotated = n ? [...entries.slice(turn % n), ...entries.slice(0, turn % n)] : entries
  return Object.fromEntries(rotated.reverse())
}

const text = fc.string({ unit: 'binary', maxLength: 40 })
const timestamp = fc.nat()
const decode = (bytes) => new TextDecoder().decode(bytes)

test('the harness fails a property that is false', () => {
  assert.throws(() => fc.assert(fc.property(fc.integer(), (n) => n + 1 === n), { numRuns: 10 }))
})

test('canonicalize: the same value always gives the same string, whatever order its keys were inserted in', () => {
  fc.assert(fc.property(json, fc.nat(), (v, turn) => {
    const once = canonicalize(v)
    return once === canonicalize(v) &&
      once === canonicalize(reorder(v, turn)) &&
      isDeepStrictEqual(JSON.parse(once), v)
  }), { numRuns: 500 })
})

test('canonicalize: a fractional or non-finite number anywhere is refused, never rounded', () => {
  const bad = fc.oneof(
    fc.double({ noNaN: false }).filter((d) => !Number.isInteger(d)),
    fc.constantFrom(Infinity, -Infinity, NaN),
  )
  fc.assert(fc.property(payload, key, bad, (p, k, n) => {
    assert.throws(() => canonicalize({ ...p, [k]: n }), TypeError)
    assert.throws(() => canonicalize([p, [n]]), TypeError)
    return true
  }), { numRuns: 300 })
})

test('buildSigningMessage: the same inputs always give the same bytes, and changing any one input changes them', () => {
  const fields = fc.tuple(text, text, text, timestamp, payload)
  const replacement = fc.tuple(text, text, text, timestamp, payload)
  fc.assert(fc.property(fields, replacement, fc.integer({ min: 0, max: 4 }), (base, other, which) => {
    fc.pre(!isDeepStrictEqual(base[which], other[which]))
    const changed = base.map((f, i) => (i === which ? other[which] : f))
    const a = buildSigningMessage(...base)
    const b = buildSigningMessage(...base)
    const c = buildSigningMessage(...changed)
    return Buffer.from(a).equals(Buffer.from(b)) && !Buffer.from(a).equals(Buffer.from(c)) &&
      decode(a).startsWith('kxco-relay-v1\n')
  }), { numRuns: 500 })
})

test('buildIntent: the signature verifies under the identity\'s public key, and fails once any field is changed', async () => {
  const names = ['operation', 'institutionKid', 'nonce', 'timestamp', 'payload', 'signature']
  await fc.assert(fc.asyncProperty(text, payload, fc.constantFrom(...names), text, payload, fc.nat(), async (operation, body, field, str, otherBody, at) => {
    const before = Math.floor(Date.now() / 1000)
    const intent = await buildIntent({ operation, institutionKid: IDENTITY.kid, payload: body, identity: IDENTITY })
    const after = Math.floor(Date.now() / 1000)
    const signed = (i) => buildSigningMessage(i.operation, i.institutionKid, i.nonce, i.timestamp, i.payload)

    assert.equal(mlDsa.verify(KEY.publicKey, signed(intent), intent.signature), true)
    assert.match(intent.nonce, /^[0-9a-f]{64}$/)
    assert.ok(intent.timestamp >= before && intent.timestamp <= after)

    const forged = { ...intent }
    if (field === 'timestamp') forged.timestamp = intent.timestamp + 1 + (at % 1000)
    else if (field === 'payload') {
      fc.pre(!isDeepStrictEqual(otherBody, body))
      forged.payload = otherBody
    } else if (field === 'signature') {
      const pos = at % intent.signature.length
      const digit = intent.signature[pos] === '0' ? '1' : '0'
      forged.signature = intent.signature.slice(0, pos) + digit + intent.signature.slice(pos + 1)
    } else {
      fc.pre(str !== intent[field])
      forged[field] = str
    }
    return mlDsa.verify(KEY.publicKey, signed(forged), forged.signature) === false
  }), RUNS)
})

test('randomNonce: always 64 lowercase hex characters, and never repeats across the run', () => {
  const seen = new Set()
  fc.assert(fc.property(fc.integer({ min: 1, max: 50 }), (n) => {
    for (let i = 0; i < n; i++) {
      const nonce = randomNonce()
      if (!/^[0-9a-f]{64}$/.test(nonce) || seen.has(nonce)) return false
      seen.add(nonce)
    }
    return true
  }), { numRuns: 200 })
  assert.ok(seen.size >= 200)
})

test('KxcoChain: the constructor refuses bad configuration with KxcoChainError', () => {
  const loopback = 'http://127.0.0.1:8545'
  const hosted = fc.webUrl().filter((u) => !['localhost', '127.0.0.1', '[::1]'].includes(new URL(u).hostname))
  const bad = fc.oneof(
    fc.constantFrom(null, '', false, 0, NaN).map((relay) => [{ relay, identity: IDENTITY }, 'BAD_CONFIG']),
    fc.constantFrom(undefined, null, '', 0, false).map((identity) => [{ relay: loopback, identity }, 'BAD_CONFIG']),
    fc.string({ unit: 'binary', maxLength: 20 }).filter((h) => h !== 'authorization' && h !== 'x-kxco-licence')
      .map((licenceHeader) => [{ relay: loopback, identity: IDENTITY, licenceHeader }, 'BAD_CONFIG']),
    hosted.map((relay) => [{ relay, identity: IDENTITY }, 'LICENCE_REQUIRED']),
  )
  // A licence in this process's environment would satisfy the hosted case, so
  // it is set aside for the length of the test.
  const saved = { KXCO_LICENCE_KEY: process.env.KXCO_LICENCE_KEY, KXCO_LICENSE_KEY: process.env.KXCO_LICENSE_KEY }
  delete process.env.KXCO_LICENCE_KEY
  delete process.env.KXCO_LICENSE_KEY
  try {
    // The same identity in a good configuration is accepted, so a refusal
    // below is about the configuration and not the stand-in.
    assert.equal(new KxcoChain({ relay: loopback, identity: IDENTITY }).relay, loopback)
    fc.assert(fc.property(bad, ([config, code]) => {
      assert.throws(() => new KxcoChain(config), (err) => err instanceof KxcoChainError && err.code === code)
      return true
    }), { numRuns: 300 })
  } finally {
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[name]
      else process.env[name] = value
    }
  }
})
