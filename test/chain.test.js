import { createServer }        from 'node:http'
import { test, before, after } from 'node:test'
import assert                   from 'node:assert/strict'

import { mlDsa, fingerprint }   from 'kxco-post-quantum'
import { KxcoChain, KxcoChainError, buildSigningMessage, buildIntent, canonicalize } from '../src/index.js'

// ── Mock relay ────────────────────────────────────────────────────────────────

let server, relayPort, lastRequest

function startMockRelay(handler) {
  return new Promise((resolve) => {
    server = createServer(async (req, res) => {
      let body = ''
      for await (const chunk of req) body += chunk

      // A v2-capable client probes GET /intents/v2/params first. This mock is
      // a v1 relay, so answer as one. Without this, JSON.parse('') threw in
      // the handler and no response was ever written.
      if (req.method === 'GET') {
        res.writeHead(503, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ ok: false, code: 'VERIFIED_PATH_UNAVAILABLE' }))
        return
      }

      lastRequest = JSON.parse(body)
      handler(lastRequest, res)
    })
    server.listen(0, '127.0.0.1', () => {
      relayPort = server.address().port
      resolve()
    })
  })
}

const TX_HASH = '0x' + 'de'.repeat(32)

function okResponse(res, extra = {}) {
  res.writeHead(200, { 'content-type': 'application/json' })
  // chainId is part of the relay contract now: the client refuses a response
  // that does not name the chain the transaction landed on. See RELAY.md.
  //
  // txHash is a real 32-byte hash rather than the old '0xdeadbeef' placeholder,
  // because the client now validates the shape. A caller stores this as proof;
  // a mock that returns something no chain could produce was testing against a
  // contract the relay does not have to meet.
  res.end(JSON.stringify({ ok: true, txHash: TX_HASH, blockNumber: 228000, chainId: 1111111, ...extra }))
}

function errResponse(res, status, code, message) {
  res.writeHead(status, { 'content-type': 'application/json' })
  res.end(JSON.stringify({ ok: false, code, error: message }))
}

// ── Mock identity ─────────────────────────────────────────────────────────────

let mockIdentity

before(async () => {
  await startMockRelay((req, res) => okResponse(res))
  const keypair = mlDsa.ml_dsa65.keygen()
  const kid     = fingerprint(keypair.publicKey).slice(0, 16)
  mockIdentity  = {
    kid,
    publicKey: keypair.publicKey,
    secretKey: keypair.secretKey,
    async sign(message) {
      return Buffer.from(mlDsa.sign(keypair.secretKey, message), 'hex')
    },
  }
})

after(() => server.close())

function makeChain(overrides = {}) {
  return new KxcoChain({
    relay:    `http://127.0.0.1:${relayPort}`,
    identity: mockIdentity,
    ...overrides,
  })
}

// ── Constructor ───────────────────────────────────────────────────────────────

test('constructor: defaults to the hosted relay, which then demands a licence', () => {
  assert.throws(
    () => new KxcoChain({ identity: mockIdentity }),
    (err) => err instanceof KxcoChainError && err.code === 'LICENCE_REQUIRED',
  )
})

test('constructor: throws if identity missing', () => {
  assert.throws(
    () => new KxcoChain({ relay: 'http://localhost' }),
    (err) => err instanceof KxcoChainError && err.code === 'BAD_CONFIG'
  )
})

test('constructor: a relay that is not a string is refused with BAD_CONFIG', () => {
  for (const relay of [123, {}, [], true]) {
    assert.throws(
      () => new KxcoChain({ relay, identity: mockIdentity }),
      (err) => err instanceof KxcoChainError && err.code === 'BAD_CONFIG',
      JSON.stringify(relay),
    )
  }
})

// ── registerInstitution ───────────────────────────────────────────────────────

test('registerInstitution: sends correct intent and returns txHash', async () => {
  const chain  = makeChain()
  const pubHex = Buffer.from(mockIdentity.publicKey).toString('hex')
  const result = await chain.registerInstitution({ publicKeyHex: pubHex, metadataUrl: 'https://example.com/meta.json' })

  assert.equal(result.txHash, TX_HASH)
  assert.equal(result.blockNumber, 228000)
  assert.equal(lastRequest.operation, 'registerInstitution')
  assert.equal(lastRequest.institutionKid, mockIdentity.kid)
  assert.equal(lastRequest.payload.publicKeyHex, pubHex)
  assert.equal(lastRequest.payload.metadataUrl, 'https://example.com/meta.json')
})

// ── issueCredential ───────────────────────────────────────────────────────────

test('issueCredential: sends correct intent', async () => {
  const chain   = makeChain()
  const userKey = mlDsa.ml_dsa65.keygen()
  const userKid = fingerprint(userKey.publicKey).slice(0, 16)
  const pubHex  = Buffer.from(userKey.publicKey).toString('hex')

  const result = await chain.issueCredential({
    userKid,
    userPublicKeyHex: pubHex,
    role:      'verified-user',
    expiresAt: 1800000000,
  })

  assert.equal(result.txHash, TX_HASH)
  assert.equal(lastRequest.operation, 'issueCredential')
  assert.equal(lastRequest.payload.userKid, userKid)
  assert.equal(lastRequest.payload.role, 'verified-user')
  assert.equal(lastRequest.payload.expiresAt, 1800000000)
})

// ── revokeCredential ──────────────────────────────────────────────────────────

test('revokeCredential: sends correct intent', async () => {
  const chain  = makeChain()
  const result = await chain.revokeCredential({ userKid: 'aabbccddeeff0011', reason: 'kyc-expired' })

  assert.equal(result.txHash, TX_HASH)
  assert.equal(lastRequest.operation, 'revokeCredential')
  assert.equal(lastRequest.payload.userKid, 'aabbccddeeff0011')
  assert.equal(lastRequest.payload.reason, 'kyc-expired')
})

// ── anchorAuditRoot ───────────────────────────────────────────────────────────

test('anchorAuditRoot: sends correct intent', async () => {
  const chain    = makeChain()
  const rootHash = 'a'.repeat(64)
  const result   = await chain.anchorAuditRoot({ rootHash, entryCount: 100 })

  assert.equal(result.txHash, TX_HASH)
  assert.equal(lastRequest.operation, 'anchorAuditRoot')
  assert.equal(lastRequest.payload.rootHash, rootHash)
  assert.equal(lastRequest.payload.entryCount, 100)
})

// ── anchorAttestation ─────────────────────────────────────────────────────────

test('anchorAttestation: sends correct intent', async () => {
  const chain       = makeChain()
  const payloadHash = 'b'.repeat(64)
  const result      = await chain.anchorAttestation({ payloadHash, purpose: 'regulatory-report' })

  assert.equal(result.txHash, TX_HASH)
  assert.equal(lastRequest.operation, 'anchorAttestation')
  assert.equal(lastRequest.payload.payloadHash, payloadHash)
  assert.equal(lastRequest.payload.purpose, 'regulatory-report')
})

// ── rotateKey ─────────────────────────────────────────────────────────────────

test('rotateKey: sends correct intent', async () => {
  const chain   = makeChain()
  const newKey  = mlDsa.ml_dsa65.keygen()
  const newKid  = fingerprint(newKey.publicKey).slice(0, 16)
  const pubHex  = Buffer.from(newKey.publicKey).toString('hex')
  const result  = await chain.rotateKey({ newKid, newPublicKeyHex: pubHex })

  assert.equal(result.txHash, TX_HASH)
  assert.equal(lastRequest.operation, 'rotateKey')
  assert.equal(lastRequest.payload.newKid, newKid)
})

// ── issueAgentCredential ──────────────────────────────────────────────────────

test('issueAgentCredential: sends correct intent', async () => {
  const chain     = makeChain()
  const agentKey  = mlDsa.ml_dsa65.keygen()
  const agentKid  = fingerprint(agentKey.publicKey).slice(0, 16)
  const pubHex    = Buffer.from(agentKey.publicKey).toString('hex')
  const scopeHash = 'c'.repeat(64)

  const result = await chain.issueAgentCredential({
    agentKid,
    agentPublicKeyHex: pubHex,
    agentType: 'llm',
    scopeHash,
    expiresAt: 1900000000,
  })

  assert.equal(result.txHash, TX_HASH)
  assert.equal(lastRequest.operation, 'issueAgentCredential')
  assert.equal(lastRequest.payload.agentKid, agentKid)
  assert.equal(lastRequest.payload.agentType, 'llm')
  assert.equal(lastRequest.payload.scopeHash, scopeHash)
  assert.equal(lastRequest.payload.expiresAt, 1900000000)
})

// ── revokeAgentCredential ─────────────────────────────────────────────────────

test('revokeAgentCredential: sends correct intent', async () => {
  const chain  = makeChain()
  const result = await chain.revokeAgentCredential({ agentKid: 'aabbccddeeff0022', reason: 'decommissioned' })

  assert.equal(result.txHash, TX_HASH)
  assert.equal(lastRequest.operation, 'revokeAgentCredential')
  assert.equal(lastRequest.payload.agentKid, 'aabbccddeeff0022')
  assert.equal(lastRequest.payload.reason, 'decommissioned')
})

// ── signature verification ────────────────────────────────────────────────────

test('intent signature is a valid ML-DSA-65 signature over the canonical message', async () => {
  const chain  = makeChain()
  const pubHex = Buffer.from(mockIdentity.publicKey).toString('hex')
  await chain.registerInstitution({ publicKeyHex: pubHex })

  const { operation, institutionKid, nonce, timestamp, payload, signature } = lastRequest
  const msg = buildSigningMessage(operation, institutionKid, nonce, timestamp, payload)

  const valid = mlDsa.verify(mockIdentity.publicKey, msg, signature)
  assert.ok(valid, 'signature must verify against institution public key')
})

// ── what the signing message will and will not carry ──────────────────────────

test('canonicalize: an object key named "__proto__" is refused with KxcoChainError, at any depth', () => {
  for (const text of ['{"__proto__":{"a":1}}', '{"a":{"__proto__":1}}', '[{"b":2,"__proto__":null}]']) {
    assert.throws(() => canonicalize(JSON.parse(text)), (err) => err instanceof KxcoChainError, text)
  }
})

test('buildIntent: a payload with a "__proto__" key is refused before anything is signed', async () => {
  let signed = false
  const identity = { kid: mockIdentity.kid, async sign() { signed = true; return new Uint8Array(0) } }
  await assert.rejects(
    buildIntent({ operation: 'anchorHash', institutionKid: identity.kid, payload: JSON.parse('{"__proto__":{"amount":999}}'), identity }),
    (err) => err instanceof KxcoChainError,
  )
  assert.equal(signed, false)
})

test('buildSigningMessage: a header field with a line break or an unpaired surrogate is refused, and a well-formed message keeps its bytes', () => {
  // Each of these would otherwise join to the same text as another intent.
  assert.throws(() => buildSigningMessage('anchorHash\ninstitutionKid: aaaa', 'bbbb', 'n', 1, {}), KxcoChainError)
  assert.throws(() => buildSigningMessage('anchorHash', 'aaaa\ninstitutionKid: bbbb', 'n', 1, {}), KxcoChainError)
  for (const bad of ['a\nb', 'a\rb', '\uD800', 'x\uDBFF', '\uDC00y']) {
    for (let field = 0; field < 4; field++) {
      const args = ['anchorHash', 'aa29f37ab7f4b2cf', 'ab'.repeat(32), 1700000000, {}]
      args[field] = bad
      assert.throws(
        () => buildSigningMessage(...args),
        (err) => err instanceof KxcoChainError && err.code === 'BAD_ARGUMENT',
        `field ${field}: ${JSON.stringify(bad)}`,
      )
    }
  }

  // A surrogate pair is a character, not an unpaired half, and passes as it did.
  const bytes = buildSigningMessage('anchorHash', 'aa29f37ab7f4b2cf', 'ab'.repeat(32), 1700000000,
    { purpose: 'café 😀', hash: 'line\nbreak' })
  assert.equal(Buffer.from(bytes).toString('utf8'), [
    'kxco-relay-v1',
    'operation: anchorHash',
    'institutionKid: aa29f37ab7f4b2cf',
    `nonce: ${'ab'.repeat(32)}`,
    'timestamp: 1700000000',
    'payload: {"hash":"line\\nbreak","purpose":"café 😀"}',
  ].join('\n'))
})

// ── error handling ────────────────────────────────────────────────────────────

test('throws KxcoChainError on relay error response', async () => {
  server.removeAllListeners('request')
  server.on('request', (req, res) => errResponse(res, 402, 'CREDIT_EXHAUSTED', 'no credit'))

  const chain = makeChain()
  await assert.rejects(
    () => chain.registerInstitution({ publicKeyHex: 'aa' }),
    (err) => err instanceof KxcoChainError && err.code === 'CREDIT_EXHAUSTED'
  )

  // restore
  server.removeAllListeners('request')
  server.on('request', (req, res) => { let b = ''; req.on('data', d => b += d); req.on('end', () => { lastRequest = JSON.parse(b); okResponse(res) }) })
})

test('throws KxcoChainError on timeout', async () => {
  server.removeAllListeners('request')
  server.on('request', (_req, _res) => { /* never respond */ })

  const chain = makeChain({ timeout: 100 })
  await assert.rejects(
    () => chain.registerInstitution({ publicKeyHex: 'aa' }),
    (err) => err instanceof KxcoChainError && err.code === 'TIMEOUT'
  )

  // restore
  server.removeAllListeners('request')
  server.on('request', (req, res) => { let b = ''; req.on('data', d => b += d); req.on('end', () => { lastRequest = JSON.parse(b); okResponse(res) }) })
})
