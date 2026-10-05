/**
 * Relay intent builder + signer.
 *
 * Every relay request is a signed JSON intent that proves the institution
 * authorised the operation. The relay validates the ML-DSA-65 signature
 * off-chain before submitting the EVM transaction.
 *
 * Signing message format (newline-delimited, UTF-8):
 *
 *   kxco-relay-v1
 *   operation: <name>
 *   institutionKid: <16-hex-char kid>
 *   nonce: <64 random hex chars>
 *   timestamp: <unix seconds>
 *   payload: <JCS-canonical JSON of the payload object>
 *
 * Replay protection: the relay rejects requests where timestamp is outside
 * ±5 minutes of server time, or where the nonce has been seen before.
 *
 * ── kxco-relay-v1.1: the algorithm inside the signed bytes ─────────────────
 *
 * v1 names no algorithm, so it means ML-DSA-65 and always will: every v1
 * signature already issued was made under that set, and v1 bytes are produced
 * exactly as before. A key from another parameter set signs v1.1, which puts
 * the algorithm on its own line directly after a different first line:
 *
 *   kxco-relay-v1.1
 *   alg: <ML-DSA-65 | ML-DSA-87>
 *   operation: <name>
 *   ... the remaining v1 lines, unchanged ...
 *
 * The first line differs, so no v1.1 message can be read as a v1 message or
 * the other way round, and the algorithm is covered by the signature, so it
 * cannot be swapped in transit. The relay still lets the KEY decide: it checks
 * the stated algorithm against the registered key's parameter set and refuses
 * a disagreement rather than trying the other set.
 */

import { canonicalize } from './jcs.js'
import { KxcoChainError } from './errors.js'

const enc = new TextEncoder()

/** The ML-DSA parameter sets an intent may name. ML-DSA-65 is the default. */
export const INTENT_ALGS = Object.freeze(['ML-DSA-65', 'ML-DSA-87'])

/** Public key length in bytes for each set (FIPS 204, table 2). */
const PUBLIC_KEY_BYTES = Object.freeze({ 'ML-DSA-65': 1952, 'ML-DSA-87': 2592 })

/**
 * The ML-DSA parameter set a public key belongs to, decided by its length.
 *
 * @param {Uint8Array|string} publicKey raw bytes, or hex with or without 0x
 * @returns {'ML-DSA-65'|'ML-DSA-87'}
 * @throws {KxcoChainError} BAD_ARGUMENT when the length is neither set's
 */
export function algForPublicKey(publicKey) {
  const length = typeof publicKey === 'string'
    ? publicKey.replace(/^0x/, '').length / 2
    : publicKey?.length
  const alg = INTENT_ALGS.find((a) => PUBLIC_KEY_BYTES[a] === length)
  if (!alg) {
    throw new KxcoChainError(
      `a ${length}-byte public key is neither ML-DSA-65 (1952 bytes) nor ML-DSA-87 (2592 bytes)`,
      { code: 'BAD_ARGUMENT' },
    )
  }
  return alg
}

function checkedAlg(alg) {
  if (!INTENT_ALGS.includes(alg)) {
    throw new KxcoChainError(
      `alg must be one of ${INTENT_ALGS.join(', ')}, got ${JSON.stringify(alg)}`,
      { code: 'BAD_ARGUMENT' },
    )
  }
  return alg
}

// Each header is one line, so a field carrying a line break could pass for the
// end of one header and the start of the next, and two different intents would
// sign the same bytes. An unpaired surrogate has no UTF-8 form: TextEncoder
// writes every one as U+FFFD, so it is refused for the same reason. JSON
// escapes both inside the payload, so only the header fields need the check.
const UNSAFE_HEADER = /[\r\n]|\p{Cs}/u

function header(name, value) {
  const text = `${value}`
  if (UNSAFE_HEADER.test(text)) {
    throw new KxcoChainError(
      `${name} must not contain a line break or an unpaired surrogate`,
      { code: 'BAD_ARGUMENT' },
    )
  }
  return `${name}: ${text}`
}

/**
 * Build the signing message for a relay intent.
 * @param {string} operation
 * @param {string} institutionKid
 * @param {string} nonce          — 64 random hex chars
 * @param {number} timestamp      — unix seconds
 * @param {object} payload
 * @param {'ML-DSA-65'|'ML-DSA-87'} [alg] Omitted: the v1 message, which
 *   means ML-DSA-65, byte for byte as before. Given: the v1.1 message, which
 *   carries the algorithm inside the signed bytes.
 * @returns {Uint8Array}
 * @throws {KxcoChainError} BAD_ARGUMENT when a header field contains a line
 *   break or an unpaired surrogate, the payload has a "__proto__" key, or alg
 *   is given and is not one of INTENT_ALGS
 */
export function buildSigningMessage(operation, institutionKid, nonce, timestamp, payload, alg) {
  const version = alg === undefined
    ? ['kxco-relay-v1']
    : ['kxco-relay-v1.1', header('alg', checkedAlg(alg))]
  return enc.encode([
    ...version,
    header('operation', operation),
    header('institutionKid', institutionKid),
    header('nonce', nonce),
    header('timestamp', timestamp),
    `payload: ${canonicalize(payload)}`,
  ].join('\n'))
}

/**
 * Generate a cryptographically random 64-hex-char nonce.
 * Node 20+ exposes globalThis.crypto; earlier versions use node:crypto.
 * @returns {string}
 */
export function randomNonce() {
  const bytes = new Uint8Array(32)
  // globalThis.crypto is available in Node 20+ and all modern browsers
  globalThis.crypto.getRandomValues(bytes)
  return Buffer.from(bytes).toString('hex')
}

/**
 * Build and sign a relay intent payload.
 *
 * @param {object} opts
 * @param {string} opts.operation
 * @param {string} opts.institutionKid
 * @param {object} opts.payload
 * @param {object} opts.identity   — KxcoIdentity (must have .kid and .sign())
 * @param {'ML-DSA-65'|'ML-DSA-87'} [opts.alg] The identity's parameter set.
 *   Omitted: a v1 intent, as before. Given: a v1.1 intent whose signed bytes
 *   and body both name it. The identity must sign with that set.
 * @returns {Promise<object>}      — the complete signed intent object
 */
export async function buildIntent({ operation, institutionKid, payload, identity, alg }) {
  const nonce     = randomNonce()
  const timestamp = Math.floor(Date.now() / 1000)
  const message   = buildSigningMessage(operation, institutionKid, nonce, timestamp, payload, alg)
  const sigBytes  = await identity.sign(message)
  const signature = Buffer.from(sigBytes).toString('hex')

  return {
    operation,
    institutionKid,
    nonce,
    timestamp,
    payload,
    signature,
    // Only on a v1.1 intent. A v1 intent keeps exactly the fields it had, so a
    // relay that predates v1.1 sees nothing new.
    ...(alg === undefined ? {} : { alg }),
  }
}
