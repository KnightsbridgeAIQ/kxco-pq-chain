/**
 * Translate a v1 call into what the on-chain verifier needs.
 *
 * The two paths take the same intent from a caller and want different things
 * from it. v1 sends a public key as hex and lets the relay decide what to hash.
 * v2 puts the arguments inside the signed message, so the client must produce
 * exactly the values the contract will reconstruct, in exactly its order. A
 * mismatch anywhere here is indistinguishable from a wrong signing key.
 *
 * Keeping the mapping in one place, beside the ARGS builders it has to agree
 * with, is the point: the failure mode is silent, so the two definitions should
 * not be able to drift apart across files.
 */

import { keccak_256 } from '@noble/hashes/sha3.js'
import { ARGS } from './intents-v2.js'
import { KxcoChainError } from './errors.js'

/** keccak256 of raw public key bytes, as the registry stores it. */
export function publicKeyHash(hex) {
  const clean = String(hex ?? '').replace(/^0x/, '')
  if (!/^[0-9a-fA-F]+$/.test(clean) || clean.length % 2) {
    throw new KxcoChainError(`expected hex public key, got '${hex}'`, { code: 'BAD_ARGUMENT' })
  }
  const bytes = Uint8Array.from(clean.match(/../g).map((b) => parseInt(b, 16)))
  return '0x' + Buffer.from(keccak_256(bytes)).toString('hex')
}

const need = (payload, field, operation) => {
  const v = payload?.[field]
  if (v === undefined || v === null || v === '') {
    throw new KxcoChainError(
      `${operation} needs '${field}' for on-chain verification`, { code: 'BAD_ARGUMENT' })
  }
  return v
}

/**
 * @returns {{ args: Array, body: object }}
 *          `args` is what goes into the signed message; `body` is the payload
 *          the relay forwards to the contract. They describe the same call and
 *          are built together so they cannot disagree.
 */
export function toV2(operation, payload = {}) {
  switch (operation) {
    case 'registerInstitution': {
      const hex = need(payload, 'publicKeyHex', operation)
      const url = payload.metadataUrl ?? ''
      return { args: ARGS.registerInstitution(publicKeyHash(hex), url),
               body: { metadataUrl: url } }
    }
    case 'rotateKey': {
      const newKid = need(payload, 'newKid', operation)
      const newHex = need(payload, 'newPublicKeyHex', operation)
      return { args: ARGS.rotateInstitutionKey(newKid, publicKeyHash(newHex)),
               body: { newKid, newPublicKeyHex: newHex } }
    }
    case 'issueCredential': {
      const userKid = need(payload, 'userKid', operation)
      const hash = publicKeyHash(need(payload, 'userPublicKeyHex', operation))
      const role = payload.role ?? ''
      const expiresAt = payload.expiresAt ?? 0
      return { args: ARGS.issueCredential(userKid, hash, role, expiresAt),
               body: { userKid, userPublicKeyHash: hash, role, expiresAt } }
    }
    case 'revokeCredential': {
      const userKid = need(payload, 'userKid', operation)
      const reason = payload.reason ?? ''
      return { args: ARGS.revokeCredential(userKid, reason), body: { userKid, reason } }
    }
    case 'anchorAuditRoot': {
      const rootHash = bytes32(need(payload, 'rootHash', operation), 'rootHash')
      const entryCount = payload.entryCount ?? 0
      return { args: ARGS.anchorAuditRoot(rootHash, entryCount), body: { rootHash, entryCount } }
    }
    case 'anchorAttestation': {
      const payloadHash = bytes32(need(payload, 'payloadHash', operation), 'payloadHash')
      const purpose = payload.purpose ?? ''
      return { args: ARGS.anchorAttestation(payloadHash, purpose), body: { payloadHash, purpose } }
    }
    case 'issueAgentCredential': {
      const agentKid = need(payload, 'agentKid', operation)
      const hash = publicKeyHash(need(payload, 'agentPublicKeyHex', operation))
      const agentType = payload.agentType ?? ''
      const scopeHash = bytes32(payload.scopeHash ?? '0x' + '00'.repeat(32), 'scopeHash')
      const expiresAt = payload.expiresAt ?? 0
      return { args: ARGS.issueAgentCredential(agentKid, hash, agentType, scopeHash, expiresAt),
               body: { agentKid, agentPublicKeyHash: hash, agentType, scopeHash, expiresAt } }
    }
    case 'revokeAgentCredential': {
      const agentKid = need(payload, 'agentKid', operation)
      const reason = payload.reason ?? ''
      return { args: ARGS.revokeAgentCredential(agentKid, reason), body: { agentKid, reason } }
    }
    default:
      // Not an error: it means this operation has no verified form, and the
      // caller should stay on v1 rather than be refused.
      return null
  }
}

function bytes32(value, field) {
  const clean = String(value).replace(/^0x/, '')
  if (!/^[0-9a-fA-F]{64}$/.test(clean)) {
    throw new KxcoChainError(`${field} must be 32 bytes of hex, got '${value}'`,
      { code: 'BAD_ARGUMENT' })
  }
  return '0x' + clean.toLowerCase()
}
