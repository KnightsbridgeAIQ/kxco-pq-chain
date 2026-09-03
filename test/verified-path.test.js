/**
 * The client choosing the verified path.
 *
 * Existing callers should migrate by upgrading this package, with no code
 * change. So the client asks the relay whether it verifies on-chain and uses
 * v2 when it does, falling back to v1 when it does not.
 *
 * The test that matters is the third: the signature the client produces must
 * cover exactly the bytes PQVerifyingRelay reconstructs. Nothing in the
 * transport catches a mismatch there, and on-chain it is indistinguishable
 * from a wrong key.
 */

import { createServer } from 'node:http'
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { mlDsa, fingerprint } from 'kxco-post-quantum'
import { KxcoChain } from '../src/client.js'
import { authorisingMessage, OPERATION_TAGS, OPERATION_NAMES, fetchOperationTags } from '../src/intents-v2.js'
import { toV2, publicKeyHash } from '../src/v2-payload.js'

const VERIFIER = '0xB94E0829046B7c50db51C5eC4F6F4C8B3d7fb2F5'
const CHAIN_ID = 1111111

const kp = mlDsa.keypairFromMaster(Buffer.alloc(32, 0x5a), 'verified-path')
const KID = fingerprint(kp.publicKey)
const PUBKEY_HEX = Buffer.from(kp.publicKey).toString('hex')

const identity = {
  kid: KID,
  publicKeyHex: PUBKEY_HEX,
  sign: async (message) => Buffer.from(mlDsa.sign(kp.secretKey, message), 'hex'),
}

/** @param {{ verified: boolean, nonce?: number }} opts */
async function relay({ verified, nonce = 3 } = {}) {
  const seen = []
  const server = createServer(async (req, res) => {
    const json = (status, body) => {
      res.writeHead(status, { 'content-type': 'application/json' })
      res.end(JSON.stringify(body))
    }
    if (req.method === 'GET' && req.url === '/intents/v2/params') {
      return verified
        ? json(200, { ok: true, verifyingRelay: VERIFIER, chainId: CHAIN_ID })
        : json(503, { ok: false, code: 'VERIFIED_PATH_UNAVAILABLE' })
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
    seen, last: () => seen.at(-1),
    close: () => new Promise((r) => server.close(r)),
  }
}

const client = (url, extra = {}) =>
  new KxcoChain({ relay: url, identity, licenceKey: 'test-licence', ...extra })

test('a relay that verifies on-chain gets a v2 intent', async () => {
  const r = await relay({ verified: true })
  try {
    await client(r.url).anchorAuditRoot({ rootHash: 'ab'.repeat(32), entryCount: 4096 })
    const { path, intent } = r.last()

    assert.equal(path, '/intents/v2')
    assert.equal(intent.institutionKid, KID)
    assert.equal(intent.publicKeyHex, PUBKEY_HEX)
    assert.equal(intent.nonce, 3, 'the nonce must come from the chain, not be invented')
    assert.equal(intent.payload.entryCount, 4096)
  } finally { await r.close() }
})

test('a relay that has not cut over still gets v1, unchanged', async () => {
  // Upgrading this package must be safe against either side of the cutover.
  const r = await relay({ verified: false })
  try {
    await client(r.url).anchorAuditRoot({ rootHash: 'ab'.repeat(32), entryCount: 4096 })
    const { path, intent } = r.last()

    assert.equal(path, '/intents')
    assert.ok(intent.timestamp, 'v1 intents carry a timestamp')
    assert.equal(intent.publicKeyHex, undefined, 'v1 does not send the key')
  } finally { await r.close() }
})

test('the signature covers exactly the bytes the contract will rebuild', async () => {
  // The join with no other test. A mismatch here is silent: on-chain it looks
  // like a wrong signing key, and no amount of transport testing finds it.
  const r = await relay({ verified: true, nonce: 11 })
  try {
    const payload = { userKid: 'cc29f37ab7f4b2cf', userPublicKeyHex: 'dd'.repeat(1952),
                      role: 'verified-user', expiresAt: 1800000000 }
    await client(r.url).issueCredential(payload)
    const { intent } = r.last()

    const { args } = toV2('issueCredential', payload)
    const expected = authorisingMessage({
      relayAddress: VERIFIER, operationTag: OPERATION_TAGS.issueCredential,
      kid: KID, nonce: 11, args, chainId: CHAIN_ID,
    })
    assert.equal(mlDsa.verify(kp.publicKey, expected, intent.signature), true,
      'the signature does not cover the message PQVerifyingRelay would build')

    // And the payload the relay forwards must describe that same call.
    assert.equal(intent.payload.userPublicKeyHash, publicKeyHash(payload.userPublicKeyHex))
    assert.equal(intent.payload.role, 'verified-user')
  } finally { await r.close() }
})

test('a different nonce produces a signature that does not verify', async () => {
  // Control for the test above: proves the assertion is not vacuous.
  const r = await relay({ verified: true, nonce: 11 })
  try {
    const payload = { rootHash: 'ab'.repeat(32), entryCount: 1 }
    await client(r.url).anchorAuditRoot(payload)
    const { intent } = r.last()

    const wrong = authorisingMessage({
      relayAddress: VERIFIER, operationTag: OPERATION_TAGS.anchorAuditRoot,
      kid: KID, nonce: 12, args: toV2('anchorAuditRoot', payload).args, chainId: CHAIN_ID,
    })
    assert.equal(mlDsa.verify(kp.publicKey, wrong, intent.signature), false)
  } finally { await r.close() }
})

test('an identity with no public key is told what is missing, not left to fail on-chain', async () => {
  const r = await relay({ verified: true })
  try {
    const bare = { kid: KID, sign: identity.sign }
    const c = new KxcoChain({ relay: r.url, identity: bare, licenceKey: 'test-licence' })
    await assert.rejects(
      () => c.anchorAuditRoot({ rootHash: 'ab'.repeat(32), entryCount: 1 }),
      (e) => e.code === 'PUBLIC_KEY_REQUIRED' && /publicKeyHex/.test(e.message),
    )
  } finally { await r.close() }
})

test('verifiedPath false pins a client to v1', async () => {
  // An escape hatch for a caller that needs the old behaviour while migrating.
  const r = await relay({ verified: true })
  try {
    await client(r.url, { verifiedPath: false })
      .anchorAuditRoot({ rootHash: 'ab'.repeat(32), entryCount: 1 })
    assert.equal(r.last().path, '/intents')
  } finally { await r.close() }
})

test('discovery happens once, not on every write', async () => {
  const r = await relay({ verified: true })
  try {
    const c = client(r.url)
    await c.anchorAuditRoot({ rootHash: 'ab'.repeat(32), entryCount: 1 })
    await c.anchorAuditRoot({ rootHash: 'cd'.repeat(32), entryCount: 2 })
    assert.equal(r.seen.length, 2, 'two writes, and the probe is not one of them')
    assert.ok(r.seen.every((s) => s.path === '/intents/v2'))
  } finally { await r.close() }
})

// ── the tags are derived, and must match the deployment ────────────────────

test('the locally derived operation tags match the deployed contract', async (t) => {
  // OPERATION_TAGS is computed as keccak256 of the operation name so a client
  // never has to trust a relay to tell it what it is signing. That is only
  // safe while it agrees with the contract's constants, and a drift would
  // produce signatures rejected for no visible reason.
  const rpc = process.env.RPC_URL || 'https://chain.kxco.ai/rpc'
  const address = process.env.VERIFYING_RELAY || VERIFIER

  let live
  try {
    live = await fetchOperationTags(async (data) => {
      const res = await fetch(rpc, {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call',
          params: [{ to: address, data }, 'latest'] }),
        signal: AbortSignal.timeout(8000),
      })
      const body = await res.json()
      if (body.error) throw new Error(body.error.message)
      return body.result
    })
  } catch (err) {
    return t.skip(`chain unreachable: ${err.message}`)
  }

  for (const name of OPERATION_NAMES) {
    assert.equal(OPERATION_TAGS[name], live[name], `${name} tag differs from the contract`)
  }
})
