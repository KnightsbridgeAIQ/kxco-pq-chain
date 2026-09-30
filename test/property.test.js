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
// order they were inserted in, and now and then `__proto__`, which
// canonicalize refuses.
const key = fc.oneof(
  { weight: 3, arbitrary: fc.string({ unit: 'binary', maxLength: 8 }) },
  { weight: 3, arbitrary: fc.string({ maxLength: 8 }) },
  { weight: 3, arbitrary: fc.nat(1000).map(String) },
  { weight: 1, arbitrary: fc.constant('__proto__') },
)
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

// Header text: mostly any text, and now and then text built from line breaks,
// header names and unpaired surrogates, the pieces that could otherwise let
// two different intents sign the same bytes.
const headerText = fc.oneof(
  { weight: 3, arbitrary: text },
  { weight: 1, arbitrary: fc.string({ unit: fc.constantFrom('a', '\n', '\r', 'institutionKid: ', 'nonce: ', '\uD800', '\uDBFF', '\uDC00', '😀'), maxLength: 6 }) },
)

// Whether a string holds a UTF-16 surrogate that is not half of a pair.
function hasLoneSurrogate(str) {
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i)
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = str.charCodeAt(i + 1)
      if (d >= 0xdc00 && d <= 0xdfff) { i++; continue }
      return true
    }
    if (c >= 0xdc00 && c <= 0xdfff) return true
  }
  return false
}
// Whether a header value could end one header line and start another, or has
// no UTF-8 form of its own.
const unsafe = (v) => typeof v === 'string' && (v.includes('\n') || v.includes('\r') || hasLoneSurrogate(v))
// Whether a value has an own key named `__proto__` anywhere in it.
function hasProto(v) {
  if (Array.isArray(v)) return v.some(hasProto)
  if (v === null || typeof v !== 'object') return false
  return Object.hasOwn(v, '__proto__') || Object.values(v).some(hasProto)
}
// Whether buildSigningMessage must refuse these five inputs.
const refused = (fields) => fields.slice(0, 4).some(unsafe) || hasProto(fields[4])

const REFUSED = Symbol('refused')
function attempt(fn) {
  try {
    return fn()
  } catch (err) {
    if (err instanceof KxcoChainError) return REFUSED
    throw err
  }
}

test('the harness fails a property that is false', () => {
  assert.throws(() => fc.assert(fc.property(fc.integer(), (n) => n + 1 === n), { numRuns: 10 }))
})

test('canonicalize: the same value always gives the same string, whatever order its keys were inserted in, and a `__proto__` key is refused with KxcoChainError', () => {
  fc.assert(fc.property(json, fc.nat(), (v, turn) => {
    if (hasProto(v)) {
      assert.throws(() => canonicalize(v), KxcoChainError)
      assert.throws(() => canonicalize(reorder(v, turn)), KxcoChainError)
      return true
    }
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
  // A `__proto__` key elsewhere in the value may be reached first, and is
  // refused in its own right.
  const refusal = (value) => (err) => err instanceof TypeError || (hasProto(value) && err instanceof KxcoChainError)
  fc.assert(fc.property(payload, key, bad, (p, k, n) => {
    const inObject = { ...p, [k]: n }
    const inArray = [p, [n]]
    assert.throws(() => canonicalize(inObject), refusal(inObject))
    assert.throws(() => canonicalize(inArray), refusal(inArray))
    return true
  }), { numRuns: 300 })
})

test('buildSigningMessage: the same inputs always give the same bytes, changing any one input changes them, and an input it cannot sign is refused with KxcoChainError', () => {
  const fields = fc.tuple(headerText, headerText, headerText, timestamp, payload)
  const replacement = fc.tuple(headerText, headerText, headerText, timestamp, payload)
  fc.assert(fc.property(fields, replacement, fc.integer({ min: 0, max: 4 }), (base, other, which) => {
    fc.pre(!isDeepStrictEqual(base[which], other[which]))
    const changed = base.map((f, i) => (i === which ? other[which] : f))
    for (const f of [base, changed]) {
      if (refused(f)) assert.throws(() => buildSigningMessage(...f), KxcoChainError)
    }
    if (refused(base) || refused(changed)) return true
    const a = buildSigningMessage(...base)
    const b = buildSigningMessage(...base)
    const c = buildSigningMessage(...changed)
    return Buffer.from(a).equals(Buffer.from(b)) && !Buffer.from(a).equals(Buffer.from(c)) &&
      decode(a).startsWith('kxco-relay-v1\n')
  }), { numRuns: 1000 })
})

test('buildSigningMessage: two different sets of header fields never give the same bytes, even with text moved across a header line', () => {
  const plain = fc.string({ unit: 'binary-ascii', maxLength: 8 })
  const LABEL = ['\ninstitutionKid: ', '\nnonce: ']
  // Pairs that would join to the same text if a field could carry a line
  // break: the tail of one field, with the next header's name, moved into the
  // field after it.
  const shifted = fc.tuple(plain, plain, plain, plain, fc.constantFrom(0, 1)).map(([p, q, r, rest, at]) => {
    const x = [p + LABEL[at] + q, r]
    const y = [p, q + LABEL[at] + r]
    return at === 0 ? [[...x, rest], [...y, rest]] : [[rest, ...x], [rest, ...y]]
  })
  // Pairs that differ only in an unpaired surrogate, which UTF-8 cannot tell
  // apart from another.
  const lone = fc.constantFrom('\uD800', '\uDBFF', '\uDC00', '\uDFFF')
  const swapped = fc.tuple(plain, lone, lone, fc.nat(2)).filter(([, u, v]) => u !== v).map(([p, u, v, at]) => {
    const x = ['anchorHash', 'aa29f37ab7f4b2cf', 'ab'.repeat(32)]
    const y = [...x]
    x[at] = p + u
    y[at] = p + v
    return [x, y]
  })
  fc.assert(fc.property(fc.oneof(shifted, swapped), timestamp, payload, ([x, y], ts, body) => {
    fc.pre(!isDeepStrictEqual(x, y))
    const a = attempt(() => buildSigningMessage(...x, ts, body))
    const b = attempt(() => buildSigningMessage(...y, ts, body))
    return a === REFUSED || b === REFUSED || !Buffer.from(a).equals(Buffer.from(b))
  }), { numRuns: 300 })
})

test('buildIntent: the signature verifies under the identity\'s public key, and fails once any field is changed; an intent it cannot sign is refused before signing', async () => {
  const names = ['operation', 'institutionKid', 'nonce', 'timestamp', 'payload', 'signature']
  await fc.assert(fc.asyncProperty(headerText, payload, fc.constantFrom(...names), headerText, payload, fc.nat(), async (operation, body, field, str, otherBody, at) => {
    if (unsafe(operation) || hasProto(body)) {
      let signed = false
      const identity = { kid: IDENTITY.kid, async sign(m) { signed = true; return IDENTITY.sign(m) } }
      await assert.rejects(buildIntent({ operation, institutionKid: IDENTITY.kid, payload: body, identity }), KxcoChainError)
      return signed === false
    }
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
    // A changed field the message cannot carry is refused rather than signed.
    const message = attempt(() => signed(forged))
    if (message === REFUSED) return field === 'payload' ? hasProto(otherBody) : unsafe(str)
    return mlDsa.verify(KEY.publicKey, message, forged.signature) === false
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
    fc.oneof(fc.integer(), fc.double(), fc.boolean(), fc.object(), fc.array(fc.webUrl(), { maxLength: 2 }))
      .map((relay) => [{ relay, identity: IDENTITY }, 'BAD_CONFIG']),
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
