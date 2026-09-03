// Version 2 intents: what an institution signs when the CHAIN verifies the
// signature rather than the relay.
//
// Version 1 signs over RFC 8785 canonical JSON (see intents.js). That is fine
// when a Node process does the verifying, and impossible when a contract does:
// reproducing JCS on-chain means JSON parsing, key sorting and string escaping
// in the EVM. So the on-chain path needs a message a contract can rebuild
// cheaply, which means ABI encoding.
//
// This is the only reason v2 exists. It is not a better v1 and it does not
// replace it — the off-chain relay keeps accepting v1 for as long as it runs.
//
// ── What is signed ──────────────────────────────────────────────────────────
//
//   abi.encodePacked(
//     abi.encode(relayAddress, chainId, operationTag, kid, nonce),
//     abi.encode(...operation arguments)
//   )
//
// The contract, the chain, the operation, the actor, a per-kid nonce and every
// argument are inside the signed bytes, so a signature authorises exactly one
// call. It cannot be replayed, pointed at a different deployment or chain, or
// reused for another operation.
//
// The timestamp from v1 is gone. An on-chain nonce is strictly better than a
// ±5 minute window: the chain already orders transactions, and a nonce cannot
// be satisfied twice.
//
// ── On getting this exactly right ───────────────────────────────────────────
//
// One wrong byte here produces a signature the contract rejects, and the
// failure is indistinguishable from a wrong key. So `PQVerifyingRelay` exposes
// `authorisingMessage(...)`, and kxco-verified-contracts' IntentsV2Encoding
// encoder against the deployed contract's own answer for every operation. The
// encoder is not trusted because it looks right; it is checked against the
// thing that will judge it.

import { mlDsa, fingerprint } from 'kxco-post-quantum'

const enc = new TextEncoder()

/** Armature L1. */
export const CHAIN_ID = 1111111

// ── minimal ABI encoding ────────────────────────────────────────────────────
//
// Only the types these operations use. A general encoder would be more code
// and more places to be subtly wrong, and every type here is checked against
// ethers and against the contract.

const WORD = 32

function word(bytes, leftAligned = false) {
  const out = new Uint8Array(WORD)
  if (leftAligned) out.set(bytes.subarray(0, WORD), 0)
  else out.set(bytes.subarray(0, WORD), WORD - bytes.length)
  return out
}

function hexToBytes(hex) {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex
  if (h.length % 2) throw new TypeError(`odd-length hex: ${hex}`)
  const out = new Uint8Array(h.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16)
  return out
}

function uintWord(value) {
  let n = BigInt(value)
  if (n < 0n) throw new RangeError('negative value')
  const out = new Uint8Array(WORD)
  for (let i = WORD - 1; i >= 0 && n > 0n; i--) {
    out[i] = Number(n & 0xffn)
    n >>= 8n
  }
  return out
}

/** `address`: 20 bytes, right-aligned. */
const addressWord = (a) => word(hexToBytes(a))
/** `bytes32`: exactly 32 bytes. */
const bytes32Word = (h) => word(hexToBytes(h))
/** `bytes8`: 8 bytes, LEFT-aligned. The opposite of how a number pads. */
const bytes8Word = (h) => word(hexToBytes(h), true)

function padRight(bytes) {
  const rem = bytes.length % WORD
  if (rem === 0) return bytes
  const out = new Uint8Array(bytes.length + (WORD - rem))
  out.set(bytes)
  return out
}

function concat(chunks) {
  const total = chunks.reduce((n, c) => n + c.length, 0)
  const out = new Uint8Array(total)
  let off = 0
  for (const c of chunks) { out.set(c, off); off += c.length }
  return out
}

/**
 * abi.encode over a list of `{ type, value }`.
 *
 * Static types occupy one head word. Dynamic types (`string`, `bytes`) put an
 * offset in the head and their length plus padded data in the tail — the
 * offset being relative to the start of the head, which is the detail most
 * hand-rolled encoders get wrong.
 */
export function abiEncode(items) {
  const head = []
  const tail = []
  let tailOffset = items.length * WORD

  for (const { type, value } of items) {
    switch (type) {
      case 'address':  head.push(addressWord(value)); break
      case 'bytes32':  head.push(bytes32Word(value)); break
      case 'bytes8':   head.push(bytes8Word(value)); break
      case 'uint256':
      case 'uint64':   head.push(uintWord(value)); break
      case 'string':
      case 'bytes': {
        const bytes = type === 'string' ? enc.encode(value) : hexToBytes(value)
        head.push(uintWord(tailOffset))
        const chunk = concat([uintWord(bytes.length), padRight(bytes)])
        tail.push(chunk)
        tailOffset += chunk.length
        break
      }
      default:
        throw new TypeError(`unsupported ABI type '${type}'`)
    }
  }
  return concat([...head, ...tail])
}

// ── operation tags ──────────────────────────────────────────────────────────
//
// keccak256 of the operation name, matching the contract's constants. Taken
// from `operationTags()` rather than recomputed, so the two cannot drift.

/** `operationTags()` — keccak256 of the signature, first four bytes. */
export const OPERATION_TAGS_SELECTOR = '0xe047006b'

/**
 * Read the operation tags from a deployed relay.
 *
 * Deliberately not hardcoded. A tag that drifted from the contract's constant
 * would produce signatures rejected for no visible reason, and the contract is
 * the authority on its own constants.
 *
 * @param {(data: string) => Promise<string>} ethCall
 *        Calls the relay with the given calldata and returns the hex result.
 */
export async function fetchOperationTags(ethCall) {
  // operationTags() -> selector
  const out = await ethCall(OPERATION_TAGS_SELECTOR)
  const hex = out.startsWith('0x') ? out.slice(2) : out
  const names = [
    'registerInstitution', 'issueCredential', 'revokeCredential', 'anchorAuditRoot',
    'anchorAttestation', 'rotateInstitutionKey', 'issueAgentCredential', 'revokeAgentCredential',
  ]
  const tags = {}
  names.forEach((n, i) => { tags[n] = '0x' + hex.slice(i * 64, (i + 1) * 64) })
  return tags
}

// ── the message ─────────────────────────────────────────────────────────────

/**
 * Build the exact bytes `PQVerifyingRelay` will verify.
 *
 * @param {object} opts
 * @param {string} opts.relayAddress   the PQVerifyingRelay deployment
 * @param {string} opts.operationTag   bytes32 from `operationTags()`
 * @param {string} opts.kid            16-hex kid, no 0x
 * @param {number|bigint} opts.nonce   the relay's current nonce for that kid
 * @param {Array<{type: string, value: any}>} opts.args  operation arguments
 * @param {number} [opts.chainId]      defaults to 1111111
 * @returns {Uint8Array}
 */
export function authorisingMessage({ relayAddress, operationTag, kid, nonce, args, chainId = CHAIN_ID }) {
  if (!/^0x[0-9a-fA-F]{40}$/.test(relayAddress)) {
    throw new TypeError(`relayAddress must be a 20-byte hex address, got '${relayAddress}'`)
  }
  if (!/^[0-9a-f]{16}$/.test(kid)) {
    throw new TypeError(`kid must be 16 lowercase hex characters, got '${kid}'`)
  }
  const prefix = abiEncode([
    { type: 'address', value: relayAddress },
    { type: 'uint256', value: chainId },
    { type: 'bytes32', value: operationTag },
    { type: 'bytes8',  value: '0x' + kid },
    { type: 'uint64',  value: nonce },
  ])
  return concat([prefix, abiEncode(args)])
}

/**
 * Sign an operation for the on-chain verifier.
 *
 * @returns {{ kid: string, nonce: string, message: Uint8Array, signature: string,
 *             publicKeyHex: string }}
 *          `signature` and `publicKeyHex` are hex without 0x, the shape the
 *          contract's `bytes calldata` parameters expect once prefixed.
 */
export function signIntentV2({ keypair, relayAddress, operationTag, nonce, args, chainId = CHAIN_ID }) {
  const kid = fingerprint(keypair.publicKey)
  const message = authorisingMessage({ relayAddress, operationTag, kid, nonce, args, chainId })
  return {
    kid,
    nonce: String(nonce),
    message,
    signature: mlDsa.sign(keypair.secretKey, message),
    publicKeyHex: Buffer.from(keypair.publicKey).toString('hex'),
  }
}

/**
 * Argument lists per operation, in the order each contract function documents.
 * Keeping them here means a caller cannot get the order wrong independently in
 * two places.
 */
export const ARGS = {
  registerInstitution: (publicKeyHash, metadataUrl) => ([
    { type: 'bytes32', value: publicKeyHash },
    { type: 'string',  value: metadataUrl },
  ]),
  rotateInstitutionKey: (newKid, newPublicKeyHash) => ([
    { type: 'bytes8',  value: '0x' + newKid },
    { type: 'bytes32', value: newPublicKeyHash },
  ]),
  issueCredential: (userKid, userPublicKeyHash, role, expiresAt) => ([
    { type: 'bytes8',  value: '0x' + userKid },
    { type: 'bytes32', value: userPublicKeyHash },
    { type: 'string',  value: role },
    { type: 'uint64',  value: expiresAt },
  ]),
  revokeCredential: (userKid, reason) => ([
    { type: 'bytes8', value: '0x' + userKid },
    { type: 'string', value: reason },
  ]),
  anchorAuditRoot: (rootHash, entryCount) => ([
    { type: 'bytes32', value: rootHash },
    { type: 'uint64',  value: entryCount },
  ]),
  anchorAttestation: (payloadHash, purpose) => ([
    { type: 'bytes32', value: payloadHash },
    { type: 'string',  value: purpose },
  ]),
  issueAgentCredential: (agentKid, agentPublicKeyHash, agentType, scopeHash, expiresAt) => ([
    { type: 'bytes8',  value: '0x' + agentKid },
    { type: 'bytes32', value: agentPublicKeyHash },
    { type: 'string',  value: agentType },
    { type: 'bytes32', value: scopeHash },
    { type: 'uint64',  value: expiresAt },
  ]),
  revokeAgentCredential: (agentKid, reason) => ([
    { type: 'bytes8', value: '0x' + agentKid },
    { type: 'string', value: reason },
  ]),
}
