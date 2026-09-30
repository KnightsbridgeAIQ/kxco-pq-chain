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
 */

import { canonicalize } from './jcs.js'
import { KxcoChainError } from './errors.js'

const enc = new TextEncoder()

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
 * @returns {Uint8Array}
 * @throws {KxcoChainError} BAD_ARGUMENT when a header field contains a line
 *   break or an unpaired surrogate, or the payload has a "__proto__" key
 */
export function buildSigningMessage(operation, institutionKid, nonce, timestamp, payload) {
  return enc.encode([
    'kxco-relay-v1',
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
 * @returns {Promise<object>}      — the complete signed intent object
 */
export async function buildIntent({ operation, institutionKid, payload, identity }) {
  const nonce     = randomNonce()
  const timestamp = Math.floor(Date.now() / 1000)
  const message   = buildSigningMessage(operation, institutionKid, nonce, timestamp, payload)
  const sigBytes  = await identity.sign(message)
  const signature = Buffer.from(sigBytes).toString('hex')

  return {
    operation,
    institutionKid,
    nonce,
    timestamp,
    payload,
    signature,
  }
}
