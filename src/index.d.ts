// ── KxcoChainError ────────────────────────────────────────────────────────────

export class KxcoChainError extends Error {
  name: 'KxcoChainError'
  code: string
  status: number | null
  body: unknown | null
}

// ── Intent types ──────────────────────────────────────────────────────────────

export interface RelayIntent {
  operation:      string
  institutionKid: string
  nonce:          string
  timestamp:      number
  payload:        Record<string, unknown>
  signature:      string
}

export interface RelayResult {
  /** Validated as 0x + 64 hex. A malformed hash throws `BAD_RELAY_RESPONSE`. */
  txHash:      string
  blockNumber: number
  /** Always 1111111. A response naming any other chain throws. */
  chainId:     1111111
  /**
   * Whether the RELAY stated the chain id, or whether `chainId` above is only
   * what this client was configured to expect.
   *
   * `true` under the default `strictChainId`, which requires the field. It can
   * be `false` only when `strictChainId: false` was passed. The escape hatch
   * is allowed to skip the check; it is not allowed to fabricate the answer,
   * so a caller storing this as proof can tell which they have.
   */
  chainIdConfirmed: boolean
}

/** Armature L1. Not configurable. */
export const CHAIN_ID: 1111111

export const DEFAULT_RELAY_URL: 'https://relay.kxco.ai'

// ── KxcoChain ─────────────────────────────────────────────────────────────────

export interface KxcoChainOptions {
  /** Relay base URL. Defaults to https://relay.kxco.ai */
  relay?:     string
  /** KxcoIdentity from kxco-pq-sdk — must have .kid (string) and .sign(Uint8Array) */
  identity:   { kid: string; sign(message: Uint8Array): Promise<Uint8Array> }
  timeout?:   number
  /**
   * Required for writes to a hosted relay. Falls back to `KXCO_LICENCE_KEY`
   * or `KXCO_LICENSE_KEY`. Signing an intent proves who you are; the licence
   * is what entitles you to have KXCO pay gas and submit the transaction.
   *
   * A missing licence throws at CONSTRUCTION, not at the first write.
   */
  licenceKey?: string
  /**
   * Which header carries the licence. Default 'authorization' (as a Bearer
   * token). Use 'x-kxco-licence' where a proxy in front of the relay consumes
   * or strips Authorization.
   */
  licenceHeader?: 'authorization' | 'x-kxco-licence'
  /**
   * Override the loopback heuristic. By default a licence is required unless
   * the relay is on localhost, so local development and tests are unaffected.
   */
  requireLicence?: boolean
  /**
   * Require the relay to name chain 1111111 in every response. Default true.
   * Set false only to talk to a relay that predates the field.
   */
  strictChainId?: boolean
  /**
   * Called with a structured record for each relay write. Off by default: a
   * library should not write to a caller's logs uninvited. Billing is metered
   * relay-side; this is for your own observability.
   */
  onUsageEvent?: (event: Record<string, unknown>) => void
}

export interface RevokeKidOpts {
  kid:     string
  reason?: string
}

export interface AnchorHashOpts {
  /** Hex SHA-256 digest. */
  hash:     string
  purpose?: string
}

export interface RegisterInstitutionOpts {
  publicKeyHex:  string
  metadataUrl?:  string
}

export interface IssueCredentialOpts {
  userKid:         string
  userPublicKeyHex: string
  role:            string
  expiresAt?:      number
}

export interface RevokeCredentialOpts {
  userKid: string
  reason?: string
}

export interface AnchorAuditRootOpts {
  rootHash:   string
  entryCount: number
}

export interface AnchorAttestationOpts {
  payloadHash: string
  purpose:     string
}

export interface RotateKeyOpts {
  newKid:          string
  newPublicKeyHex: string
}

export class KxcoChain {
  constructor(opts: KxcoChainOptions)
  /** The relay this client writes to. */
  readonly relay: string
  /** Whether a licence key is configured. Never exposes the key. */
  readonly licensed: boolean

  registerInstitution(opts: RegisterInstitutionOpts): Promise<RelayResult>
  /** The same wire operation as `registerInstitution`. */
  registerIdentity(opts: RegisterInstitutionOpts):          Promise<RelayResult>
  /** Revoke a key outright. `revokeCredential` revokes an issued credential. */
  revokeKid(opts: RevokeKidOpts):                           Promise<RelayResult>
  /** Anchor any hex SHA-256 digest. The general form of the two anchors below. */
  anchorHash(opts: AnchorHashOpts):                         Promise<RelayResult>
  /** The same wire operation as `issueAgentCredential`. */
  registerAgent(opts: IssueAgentCredentialOpts):            Promise<RelayResult>
  issueCredential(opts: IssueCredentialOpts):               Promise<RelayResult>
  revokeCredential(opts: RevokeCredentialOpts):             Promise<RelayResult>
  anchorAuditRoot(opts: AnchorAuditRootOpts):               Promise<RelayResult>
  anchorAttestation(opts: AnchorAttestationOpts):           Promise<RelayResult>
  rotateKey(opts: RotateKeyOpts):                           Promise<RelayResult>
  issueAgentCredential(opts: IssueAgentCredentialOpts):     Promise<RelayResult>
  revokeAgentCredential(opts: RevokeAgentCredentialOpts):   Promise<RelayResult>
}

export interface IssueAgentCredentialOpts {
  agentKid:          string
  agentPublicKeyHex: string
  agentType:         'llm' | 'robot' | 'iot' | 'process'
  scopeHash:         string
  expiresAt:         number
}

export interface RevokeAgentCredentialOpts {
  agentKid: string
  reason?:  string
}

// ── Low-level helpers ─────────────────────────────────────────────────────────

export function buildSigningMessage(
  operation:      string,
  institutionKid: string,
  nonce:          string,
  timestamp:      number,
  payload:        Record<string, unknown>,
): Uint8Array

export function randomNonce(): string

export function buildIntent(opts: {
  operation:      string
  institutionKid: string
  payload:        Record<string, unknown>
  identity:       { kid: string; sign(message: Uint8Array): Promise<Uint8Array> }
}): Promise<RelayIntent>

export function canonicalize(value: unknown): string
