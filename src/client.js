/**
 * KxcoChain — HTTP client for the KXCO meta-transaction relay.
 *
 * Institutions never interact with Armature L1 directly. This client sends
 * ML-DSA-65 signed intents to the KXCO relay, which validates the signature and
 * submits the EVM transaction on the institution's behalf. Your institution
 * never holds ARMR, never runs a node, and never sets a gas price.
 *
 * Two things are enforced here that were not before, and both are deliberate.
 *
 * A licence key is required for writes to a hosted relay. Signing an intent
 * proves who you are; it does not entitle you to have KXCO pay gas and submit
 * the transaction. The client refuses before it sends rather than letting the
 * relay answer 401, because a typed error at the call site is more use than an
 * HTTP status three layers down. Loopback relays need no licence, so local
 * development and the test suite are unaffected.
 *
 * The relay's answer must name Armature L1. A response that reports a
 * transaction on some other chain is not a transaction this client asked for,
 * and returning its hash to a caller who is about to store it as proof would be
 * worse than failing.
 */

import { OPERATION_TAGS, authorisingMessage, abiEncode } from './intents-v2.js'
import { toV2 } from './v2-payload.js'
import { buildIntent } from './intents.js'
import { KxcoChainError } from './errors.js'

/** Armature L1. Not configurable. */
export const CHAIN_ID = 1111111

export const DEFAULT_RELAY_URL = 'https://relay.kxco.ai'

// A relay on the loopback interface is a mock or a local node, so a licence is
// not required to talk to it. Anything else is treated as hosted, because the
// failure that matters is shipping to production with no licence configured,
// not running a test.
function isLoopback(url) {
  try {
    const { hostname } = new URL(url)
    return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1' || hostname === '[::1]'
  } catch {
    return false
  }
}

export class KxcoChain {
  #relay
  #identity
  #timeout
  #licenceKey
  #licenceHeader
  #requireLicence
  #strictChainId
  #publicKeyHex
  #v2
  #onUsageEvent

  /**
   * @param {object} opts
   * @param {string} [opts.relay]        — relay base URL. Defaults to https://relay.kxco.ai
   * @param {object} opts.identity       — KxcoIdentity from kxco-pq-sdk (needs .kid and .sign())
   * @param {number} [opts.timeout]      — request timeout in ms (default 10000)
   * @param {string} [opts.licenceKey]   — required for a hosted relay. Falls back to
   *                                       KXCO_LICENCE_KEY / KXCO_LICENSE_KEY.
   * @param {'authorization'|'x-kxco-licence'} [opts.licenceHeader]
   *        Which header carries it. Default 'authorization'. Use the other where a
   *        proxy in front of the relay consumes or strips Authorization.
   * @param {boolean} [opts.requireLicence] — override the loopback heuristic.
   * @param {boolean} [opts.strictChainId]  — require the relay to name chain 1111111
   *                                          in its response. Default true.
   * @param {(event: object) => void} [opts.onUsageEvent]
   *        Called with a structured record for each relay write. Off by default:
   *        a library should not write to a caller's logs uninvited. Billing is
   *        metered relay-side; this is here for your own observability.
   */
  constructor({
    relay = DEFAULT_RELAY_URL,
    identity,
    timeout = 10_000,
    licenceKey,
    licenceHeader = 'authorization',
    requireLicence,
    strictChainId = true,
    onUsageEvent,
    publicKeyHex,
    verifiedPath,
  } = {}) {
    if (!relay) throw new KxcoChainError('relay URL is required', { code: 'BAD_CONFIG' })
    if (!identity) throw new KxcoChainError('identity is required', { code: 'BAD_CONFIG' })

    if (licenceHeader !== 'authorization' && licenceHeader !== 'x-kxco-licence') {
      throw new KxcoChainError(
        `licenceHeader must be 'authorization' or 'x-kxco-licence', got '${licenceHeader}'`,
        { code: 'BAD_CONFIG' },
      )
    }

    this.#relay = relay.replace(/\/$/, '')
    this.#identity = identity
    this.#timeout = timeout
    this.#licenceKey =
      licenceKey ?? globalThis.process?.env?.KXCO_LICENCE_KEY ?? globalThis.process?.env?.KXCO_LICENSE_KEY ?? null
    this.#licenceHeader = licenceHeader
    this.#requireLicence = requireLicence ?? !isLoopback(this.#relay)
    this.#strictChainId = strictChainId
    this.#onUsageEvent = onUsageEvent ?? null
    // Needed only on the verified path, where the key travels with the call so
    // the chain can check it against the registry. identity exposes it on the
    // SDK's KxcoIdentity; pass it explicitly for any other implementation.
    this.#publicKeyHex = publicKeyHex ?? identity.publicKeyHex ??
      (identity.publicKey ? Buffer.from(identity.publicKey).toString('hex') : null)
    // undefined = not probed, null = not available on this relay.
    this.#v2 = verifiedPath === false ? null : undefined

    // Fail at construction, not at the first write. A service that boots
    // without a licence and only discovers it when the first credential is
    // issued has already told a user their onboarding succeeded.
    if (this.#requireLicence && !this.#licenceKey) {
      throw new KxcoChainError(
        `writing to ${this.#relay} requires a licence key. Set KXCO_LICENCE_KEY, or pass ` +
        'licenceKey. Signing an intent proves who you are; the licence is what entitles ' +
        'you to have KXCO pay gas and submit the transaction. Reading chain state is free ' +
        'and needs none.',
        { code: 'LICENCE_REQUIRED' },
      )
    }
  }

  /** The relay this client writes to. */
  get relay() { return this.#relay }

  /** Whether a licence key is configured. Never exposes the key itself. */
  get licensed() { return this.#licenceKey !== null }

  // ─── identity ────────────────────────────────────────────────────────────

  /**
   * Register an institution on-chain. Called once during onboarding.
   * @param {{ publicKeyHex: string, metadataUrl?: string }} opts
   */
  async registerInstitution({ publicKeyHex, metadataUrl = '' }) {
    return this.#send('registerInstitution', { publicKeyHex, metadataUrl })
  }

  /**
   * Register an identity on-chain. The same wire operation as
   * `registerInstitution`, under the name the rest of the stack uses.
   * @param {{ publicKeyHex: string, metadataUrl?: string }} opts
   */
  async registerIdentity(opts) {
    return this.registerInstitution(opts)
  }

  /**
   * Record an institution key rotation on-chain.
   * @param {{ newKid: string, newPublicKeyHex: string }} opts
   */
  async rotateKey({ newKid, newPublicKeyHex }) {
    return this.#send('rotateKey', { newKid, newPublicKeyHex }, { kid: newKid })
  }

  /**
   * Revoke a kid on-chain, whatever it belongs to.
   *
   * `revokeCredential` revokes a user credential the institution issued.
   * This revokes a key outright, which is what a registry lookup reads when it
   * answers `revoked`.
   *
   * @param {{ kid: string, reason?: string }} opts
   */
  async revokeKid({ kid, reason = '' }) {
    if (!kid) throw new KxcoChainError('revokeKid: kid is required', { code: 'BAD_ARGUMENT' })
    return this.#send('revokeKid', { kid, reason }, { kid })
  }

  /**
   * Record a user credential issuance on-chain.
   * @param {{ userKid: string, userPublicKeyHex: string, role: string, expiresAt?: number }} opts
   */
  async issueCredential({ userKid, userPublicKeyHex, role, expiresAt = 0 }) {
    return this.#send('issueCredential', { userKid, userPublicKeyHex, role, expiresAt }, { kid: userKid })
  }

  /**
   * Revoke a user credential on-chain.
   * @param {{ userKid: string, reason?: string }} opts
   */
  async revokeCredential({ userKid, reason = '' }) {
    return this.#send('revokeCredential', { userKid, reason }, { kid: userKid })
  }

  // ─── anchors ─────────────────────────────────────────────────────────────

  /**
   * Anchor an arbitrary hash on-chain.
   *
   * The general form. `anchorAuditRoot` and `anchorAttestation` are the two
   * shapes with their own on-chain semantics; this one takes any digest.
   *
   * @param {{ hash: string, purpose?: string }} opts — hash is hex SHA-256
   */
  async anchorHash({ hash, purpose = '' }) {
    if (!/^[0-9a-f]{64}$/i.test(hash ?? '')) {
      throw new KxcoChainError('anchorHash: hash must be a hex SHA-256 digest', { code: 'BAD_ARGUMENT' })
    }
    return this.#send('anchorHash', { hash, purpose })
  }

  /**
   * Anchor an audit log checkpoint on-chain.
   * @param {{ rootHash: string, entryCount: number }} opts
   */
  async anchorAuditRoot({ rootHash, entryCount }) {
    return this.#send('anchorAuditRoot', { rootHash, entryCount })
  }

  /**
   * Anchor an attestation envelope hash on-chain.
   * @param {{ payloadHash: string, purpose: string }} opts
   */
  async anchorAttestation({ payloadHash, purpose }) {
    return this.#send('anchorAttestation', { payloadHash, purpose })
  }

  // ─── agents ──────────────────────────────────────────────────────────────

  /**
   * Register an AI agent or robot identity on-chain, sponsored by this institution.
   * @param {{ agentKid: string, agentPublicKeyHex: string,
   *           agentType: 'llm'|'robot'|'iot'|'process',
   *           scopeHash: string, expiresAt: number }} opts
   */
  async issueAgentCredential({ agentKid, agentPublicKeyHex, agentType, scopeHash, expiresAt }) {
    return this.#send(
      'issueAgentCredential',
      { agentKid, agentPublicKeyHex, agentType, scopeHash, expiresAt },
      { kid: agentKid },
    )
  }

  /**
   * Register an agent. The same wire operation as `issueAgentCredential`,
   * under the name the rest of the stack uses.
   */
  async registerAgent(opts) {
    return this.issueAgentCredential(opts)
  }

  /**
   * Revoke an agent credential on-chain.
   * @param {{ agentKid: string, reason?: string }} opts
   */
  async revokeAgentCredential({ agentKid, reason = '' }) {
    return this.#send('revokeAgentCredential', { agentKid, reason }, { kid: agentKid })
  }

  // ─── internal ────────────────────────────────────────────────────────────

  #headers() {
    const headers = { 'content-type': 'application/json' }
    if (this.#licenceKey) {
      headers[this.#licenceHeader] =
        this.#licenceHeader === 'authorization' ? `Bearer ${this.#licenceKey}` : this.#licenceKey
    }
    return headers
  }

  #emit(operation, meta, result) {
    if (!this.#onUsageEvent) return
    this.#onUsageEvent({
      event: 'relay_post',
      at: new Date().toISOString(),
      chainId: CHAIN_ID,
      operation,
      institutionKid: this.#identity.kid,
      ...(meta.kid ? { kid: meta.kid } : {}),
      // A prefix attributes the event and is useless to whoever reads the log.
      // The whole key must never reach one.
      licencePrefix: this.#licenceKey ? this.#licenceKey.slice(0, 8) : null,
      txHash: result.txHash,
      blockNumber: result.blockNumber,
    })
  }

  /**
   * Does this relay verify on-chain?
   *
   * Asked once and cached. A relay that has not cut over answers 503 and the
   * client stays on v1, so upgrading this package is safe against either.
   */
  async #discoverV2() {
    if (this.#v2 !== undefined) return this.#v2
    try {
      // Deliberately shorter than the write timeout. This is a capability
      // probe, and a relay that does not answer it promptly is one that does
      // not have the endpoint. Making a caller wait the full write timeout to
      // learn that, once per process, is not worth it.
      const res = await fetch(`${this.#relay}/intents/v2/params`, {
        headers: this.#headers(),
        signal: AbortSignal.timeout(Math.min(this.#timeout, 3_000)),
      })
      const body = await res.json().catch(() => null)
      this.#v2 = res.ok && body?.ok && body.verifyingRelay
        ? { verifyingRelay: body.verifyingRelay, chainId: body.chainId ?? CHAIN_ID }
        : null
    } catch {
      // A relay that cannot be asked is treated as v1. Guessing the other way
      // would send a verified intent that the relay cannot process at all.
      this.#v2 = null
    }
    return this.#v2
  }

  /** The contract's current nonce for this identity. Not guessable. */
  async #nonce(kid) {
    const res = await fetch(`${this.#relay}/intents/v2/nonce/${kid}`, {
      headers: this.#headers(),
      signal: AbortSignal.timeout(this.#timeout),
    })
    const body = await res.json().catch(() => null)
    if (!res.ok || !body?.ok || !Number.isInteger(body.nonce)) {
      throw new KxcoChainError(
        body?.error ?? `could not read the on-chain nonce (${res.status})`,
        { code: body?.code ?? 'NONCE_UNAVAILABLE', status: res.status },
      )
    }
    return body.nonce
  }

  /**
   * Build and sign a v2 intent, or return null if this call cannot take the
   * verified path and should fall back to v1.
   */
  async #buildV2(operation, payload) {
    const v2 = await this.#discoverV2()
    if (!v2) return null

    const mapped = toV2(operation, payload)
    if (!mapped) return null            // operation has no verified form

    if (!this.#publicKeyHex) {
      throw new KxcoChainError(
        `${this.#relay} verifies signatures on-chain, which requires this identity's ` +
        'public key to travel with the call. Pass publicKeyHex to the constructor, or ' +
        'use an identity that exposes it.',
        { code: 'PUBLIC_KEY_REQUIRED' },
      )
    }

    const kid = this.#identity.kid
    const nonce = operation === 'registerInstitution' ? 0 : await this.#nonce(kid)
    const message = authorisingMessage({
      relayAddress: v2.verifyingRelay,
      operationTag: OPERATION_TAGS[operation === 'rotateKey' ? 'rotateInstitutionKey' : operation],
      kid, nonce, args: mapped.args, chainId: v2.chainId,
    })
    const signature = Buffer.from(await this.#identity.sign(message)).toString('hex')

    return {
      operation, institutionKid: kid, publicKeyHex: this.#publicKeyHex,
      signature, nonce, payload: mapped.body,
    }
  }

  async #send(operation, payload, meta = {}) {
    // Prefer the verified path where the relay offers it. Same public API, and
    // the difference is who the chain records as having authorised the write:
    // the relay, or the institution. Falls back silently to v1 so upgrading
    // this package works against a relay either side of the cutover.
    const v2Intent = await this.#buildV2(operation, payload)
    const path = v2Intent ? '/intents/v2' : '/intents'
    const intent = v2Intent ?? await buildIntent({
      operation,
      institutionKid: this.#identity.kid,
      payload,
      identity: this.#identity,
    })

    const ac = new AbortController()
    const tid = setTimeout(() => ac.abort(), this.#timeout)

    let response
    try {
      response = await fetch(`${this.#relay}${path}`, {
        method: 'POST',
        headers: this.#headers(),
        body: JSON.stringify(intent),
        signal: ac.signal,
      })
    } catch (err) {
      clearTimeout(tid)
      if (err.name === 'AbortError') {
        throw new KxcoChainError(`relay request timed out after ${this.#timeout}ms`, { code: 'TIMEOUT' })
      }
      throw new KxcoChainError(`relay request failed: ${err.message}`, { code: 'NETWORK_ERROR' })
    }
    clearTimeout(tid)

    let body
    try {
      body = await response.json()
    } catch {
      throw new KxcoChainError('relay returned non-JSON response', {
        code: 'PARSE_ERROR',
        status: response.status,
      })
    }

    // 401 and 403 are the licence answers. Naming them is worth a line: a
    // caller reading "relay error 401" has to go and find out what the relay
    // meant by it.
    if (response.status === 401 || response.status === 403) {
      throw new KxcoChainError(
        body.error ?? `relay rejected the licence for this ${operation} (${response.status})`,
        { code: body.code ?? 'LICENCE_REJECTED', status: response.status, body },
      )
    }

    if (!response.ok || body.ok === false) {
      throw new KxcoChainError(body.error ?? `relay error ${response.status}`, {
        code: body.code ?? 'RELAY_ERROR',
        status: response.status,
        body,
      })
    }

    // A response naming another chain is not the transaction we asked for.
    // Handing its hash back to a caller who is about to store it as proof
    // would be worse than failing.
    if (body.chainId !== undefined && body.chainId !== CHAIN_ID) {
      throw new KxcoChainError(
        `relay reported a transaction on chain ${body.chainId}, expected ${CHAIN_ID} (Armature L1)`,
        { code: 'WRONG_CHAIN', status: response.status, body },
      )
    }
    const chainIdConfirmed = body.chainId !== undefined
    if (!chainIdConfirmed && this.#strictChainId) {
      throw new KxcoChainError(
        `relay response did not name a chain id. This client requires chainId ${CHAIN_ID} in ` +
        'every response so an anchor can be proved to be on Armature L1. Pass ' +
        'strictChainId: false to accept a relay that predates the field.',
        { code: 'MISSING_CHAIN_ID', status: response.status, body },
      )
    }

    // A transaction hash is what the caller stores as proof. If the relay sends
    // something that is not one, that is the relay's bug, and it has to surface
    // here where the relay can be named. Left unchecked it would travel into an
    // envelope and reappear much later as "this envelope is not anchored",
    // pointing the blame at the wrong component.
    if (typeof body.txHash !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(body.txHash)) {
      throw new KxcoChainError(
        `relay returned a malformed transaction hash for ${operation}: ${JSON.stringify(body.txHash)}`,
        { code: 'BAD_RELAY_RESPONSE', status: response.status, body },
      )
    }
    if (!Number.isInteger(body.blockNumber) || body.blockNumber < 0) {
      throw new KxcoChainError(
        `relay returned a malformed block number for ${operation}: ${JSON.stringify(body.blockNumber)}`,
        { code: 'BAD_RELAY_RESPONSE', status: response.status, body },
      )
    }

    const result = {
      txHash: body.txHash,
      blockNumber: body.blockNumber,
      chainId: CHAIN_ID,
      // Whether the RELAY said which chain, or whether this is only what this
      // client was configured to expect.
      //
      // Without this flag, `strictChainId: false` would return chainId 1111111
      // on a response that never mentioned a chain — inventing the one fact the
      // caller is about to store as proof. The escape hatch is allowed to skip
      // the check; it is not allowed to fabricate the answer.
      chainIdConfirmed,
    }
    this.#emit(operation, meta, result)
    return result
  }
}
