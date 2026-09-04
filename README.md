# kxco-pq-chain

HTTP client for the KXCO post-quantum identity relay.

[![npm](https://img.shields.io/npm/v/kxco-pq-chain?label=npm)](https://www.npmjs.com/package/kxco-pq-chain)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
[![node](https://img.shields.io/badge/node-%3E%3D20.19-brightgreen)](#install)
[![CI](https://github.com/KnightsbridgeAIQ/kxco-pq-chain/actions/workflows/ci.yml/badge.svg)](https://github.com/KnightsbridgeAIQ/kxco-pq-chain/actions/workflows/ci.yml)


Institutions sign ML-DSA-65 intents with their existing post-quantum key, POST them to the KXCO relay at `https://relay.kxco.ai`, and receive a transaction hash. KXCO validates the signature, pays gas in ARMR, and submits the EVM transaction on Armature L1. No wallets, no gas, no Ethereum node required.


## Release integrity

Every release of this package is checkable without asking us for anything.

- **Provenance.** Each release carries a SLSA provenance attestation tying the
  published tarball to the commit and workflow that built it. Verify with
  `npm audit signatures`, or read it directly from
  `registry.npmjs.org/-/npm/v1/attestations/kxco-pq-chain@<version>`.
- **Bill of materials.** A CycloneDX SBOM is published as a GitHub Release asset
  at `releases/download/v<version>/sbom.cyclonedx.json`, a permanent
  unauthenticated URL. Not an expiring build artifact.
- **Pinned where it matters.** Third-party dependencies are pinned to exact
  versions, never ranges, so the code that performs the cryptography cannot
  change without a release. Sibling `kxco-*` packages sit on caret ranges
  deliberately: it means a correctness fix in the base package reaches you
  without a release of every package above it. That is not theoretical. When
  `@noble/post-quantum` 0.7.1 was found to fail NIST SLH-DSA verification
  vectors, the revert in the base package propagated here on the next install.
  Every GitHub Action is pinned by 40-character commit SHA.
- **Conformance underneath.** The cryptography comes from
  [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), which
  is run against **2,103 NIST ACVP vectors: 1,793 passed, 0 failed, 310 skipped** and a **225-check
  cross-implementation interoperability matrix** against liboqs, Bouncy Castle
  and two pure-Python implementations, in both directions and with negative
  controls. Its published tarball also rebuilds bit-for-bit from its own tag,
  verified in CI on every run.

## Armature L1 at a glance

| | |
|---|---|
| Network | Armature L1 — permissioned, EVM-compatible settlement layer |
| Chain ID | 1111111 |
| Consensus | QBFT PoA, instant finality (~2 s target block time) |
| PQ verification | On-chain ML-DSA-65 — precompile `0x0b` (NIST FIPS 204) |
| Token | ARMR (gas paid by the KXCO relay — clients hold no crypto) |
| Explorer & docs | [chain.kxco.ai](https://chain.kxco.ai) |

---

## When to use this

Any institution backend that needs on-chain credential management — registering identities, issuing and revoking credentials, anchoring audit roots, rotating keys — without running an Ethereum node or holding crypto. If you already have a `KxcoIdentity` from `kxco-pq-sdk`, this is the only client you need to write to the chain.

For reading chain state (querying registered identities, verifying credentials on-chain), use `ethers.js` directly against `https://chain.kxco.ai/rpc`.

---

## Install

```bash
npm install kxco-pq-chain
```

Requires Node.js 20.19 or later. `kxco-post-quantum` is installed automatically as a dependency.

---

## Quick start

```js
import { KxcoChain } from 'kxco-pq-chain'

// identity is a KxcoIdentity from kxco-pq-sdk (must expose .kid and .sign())
const chain = new KxcoChain({
  identity:   institutionIdentity,
  licenceKey: process.env.KXCO_LICENCE_KEY,  // or set the env var and omit this
  // relay defaults to https://relay.kxco.ai
  timeout:    10_000,                        // optional, ms, default 10 000
})

// Register the institution on-chain — called once during onboarding
const { txHash, blockNumber } = await chain.registerInstitution({
  publicKeyHex: Buffer.from(institutionIdentity.publicKey).toString('hex'),
  metadataUrl:  'https://example.com/institution.json',  // optional
})

// Record a user credential issuance on-chain
const result = await chain.issueCredential({
  userKid:          'aa29f37ab7f4b2cf',
  userPublicKeyHex: Buffer.from(userPublicKey).toString('hex'),
  role:             'verified-user',
  expiresAt:        1800000000,  // unix seconds; omit or 0 for no expiry
})
```

All methods return `Promise<{ txHash: string, blockNumber: number, chainId: 1111111 }>` and throw `KxcoChainError` on failure.

Writes to the hosted relay **require a licence key**. Without one the constructor throws `LICENCE_REQUIRED` immediately — at boot, not at the first write, so a service cannot come up looking healthy and fail on a customer's first credential. A relay on `localhost` needs no licence, so local development and CI are unaffected.

---

## How it works

Your backend constructs an intent describing the operation (register, issue, revoke, anchor, rotate), signs the canonical signing message with your ML-DSA-65 private key, and POSTs the signed intent to `https://relay.kxco.ai/intents`. The relay verifies the signature against the institution public key registered on Armature L1, checks the nonce to prevent replays, and submits the corresponding EVM transaction. It returns the `txHash` and `blockNumber` once the transaction is included. Your institution never holds ARMR, never configures an RPC endpoint, and is billed monthly via invoice.

---

## API

All methods are on a `KxcoChain` instance and return `Promise<{ txHash: string, blockNumber: number, chainId: 1111111 }>`.

`chainId` is asserted, not decorative: a response naming another chain throws `WRONG_CHAIN`, and a response with no chain id throws `MISSING_CHAIN_ID`. See [`RELAY.md`](RELAY.md) for the full server contract.

### `new KxcoChain(opts)`

| Parameter | Type | Required | Description |
|---|---|---|---|
| `opts.identity` | `{ kid: string; sign(msg: Uint8Array): Promise<Uint8Array> }` | yes | `KxcoIdentity` from `kxco-pq-sdk` or any object with `.kid` and `.sign()` |
| `opts.relay` | `string` | no | Relay base URL. Default: `'https://relay.kxco.ai'` |
| `opts.licenceKey` | `string` | for a hosted relay | Falls back to `KXCO_LICENCE_KEY` / `KXCO_LICENSE_KEY`. Missing throws at construction |
| `opts.licenceHeader` | `'authorization' \| 'x-kxco-licence'` | no | Which header carries it. Default `'authorization'`, as a Bearer token |
| `opts.requireLicence` | `boolean` | no | Overrides the loopback heuristic in both directions |
| `opts.strictChainId` | `boolean` | no | Require `chainId` in every response. Default `true` |
| `opts.timeout` | `number` | no | Request timeout in ms. Default: `10000` |
| `opts.onUsageEvent` | `(event) => void` | no | Structured record per write, for your own observability. Off by default |

Read-only: `chain.relay` and `chain.licensed`. The licence key itself is never exposed.

---

### `chain.registerInstitution({ publicKeyHex, metadataUrl? })`

Register an institution on-chain. Called once during onboarding.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `publicKeyHex` | `string` | yes | Hex-encoded 1952-byte ML-DSA-65 public key |
| `metadataUrl` | `string` | no | URL of institution metadata JSON |

---

### `chain.issueCredential({ userKid, userPublicKeyHex, role, expiresAt? })`

Record a user credential issuance on-chain.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `userKid` | `string` | yes | 16-hex-char kid of the issued user |
| `userPublicKeyHex` | `string` | yes | Hex-encoded user ML-DSA-65 public key |
| `role` | `string` | yes | Role string, e.g. `'verified-user'` |
| `expiresAt` | `number` | no | Unix seconds. Omit or `0` for no expiry |

---

### `chain.revokeCredential({ userKid, reason? })`

Revoke a user credential on-chain.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `userKid` | `string` | yes | kid of the user whose credential is revoked |
| `reason` | `string` | no | Human-readable revocation reason |

---

### `chain.anchorAuditRoot({ rootHash, entryCount })`

Anchor an audit log checkpoint on-chain.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `rootHash` | `string` | yes | Hex SHA-256 of the latest audit log entry hash (64 hex chars) |
| `entryCount` | `number` | yes | Total entries in the log at checkpoint time |

---

### `chain.anchorAttestation({ payloadHash, purpose })`

Anchor a high-value attestation envelope hash on-chain.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `payloadHash` | `string` | yes | Hex SHA-256 of the signed attestation envelope (64 hex chars) |
| `purpose` | `string` | yes | Purpose string, e.g. `'regulatory-report'` |

---

### `chain.revokeKid({ kid, reason? })`

Revoke a key outright. This is what a registry lookup reads when it answers `revoked`, so it is the operation that makes `anchored+live` verification start refusing envelopes signed by that key.

`revokeCredential` revokes a credential the institution issued to a user; this revokes the key itself.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `kid` | `string` | yes | 16-hex-char kid to revoke |
| `reason` | `string` | no | Human-readable revocation reason |

New wire operation in 2.0.0. A relay that has not implemented it answers `400 UNKNOWN_OPERATION`.

---

### `chain.anchorHash({ hash, purpose? })`

Anchor any hex SHA-256 digest on-chain. The general form of `anchorAuditRoot` and `anchorAttestation`, which keep their own on-chain semantics.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `hash` | `string` | yes | Hex SHA-256 digest (64 hex chars) |
| `purpose` | `string` | no | Purpose string, e.g. `'quarterly-report'` |

New wire operation in 2.0.0.

---

### `chain.registerIdentity(...)` and `chain.registerAgent(...)`

Names over the existing `registerInstitution` and `issueAgentCredential` wire operations, so the rest of the stack can use one vocabulary. Identical arguments, identical bytes on the wire.

---

### `chain.rotateKey({ newKid, newPublicKeyHex })`

Record an institution key rotation on-chain.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `newKid` | `string` | yes | New 16-hex-char kid after rotation |
| `newPublicKeyHex` | `string` | yes | Hex-encoded new ML-DSA-65 public key |

---

### `chain.issueAgentCredential({ agentKid, agentPublicKeyHex, agentType, scopeHash, expiresAt })`

Register an AI agent or machine identity on-chain. Called by the sponsoring institution.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `agentKid` | `string` | yes | 16-hex-char kid of the agent |
| `agentPublicKeyHex` | `string` | yes | Hex-encoded agent ML-DSA-65 public key |
| `agentType` | `'llm' \| 'robot' \| 'iot' \| 'process'` | yes | Agent category |
| `scopeHash` | `string` | yes | Hex SHA-256 of the canonical scope JSON |
| `expiresAt` | `number` | yes | Unix seconds — mandatory, must be greater than 0 |

---

### `chain.revokeAgentCredential({ agentKid, reason? })`

Revoke an agent credential on-chain. The signing identity must be the sponsoring institution.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `agentKid` | `string` | yes | kid of the agent to revoke |
| `reason` | `string` | no | Human-readable revocation reason |

---

## Error handling

All methods throw `KxcoChainError` on failure.

```js
import { KxcoChain, KxcoChainError } from 'kxco-pq-chain'

try {
  await chain.issueCredential({ ... })
} catch (err) {
  if (err instanceof KxcoChainError) {
    console.error(err.code)    // 'TIMEOUT', 'NETWORK_ERROR', 'RELAY_ERROR', ...
    console.error(err.status)  // HTTP status or null
    console.error(err.body)    // raw relay response or null
  }
}
```

Common codes: `BAD_CONFIG`, `TIMEOUT`, `NETWORK_ERROR`, `PARSE_ERROR`, `RELAY_ERROR`, plus relay-specific codes such as `CREDIT_EXHAUSTED`.

---

## Low-level helpers

Exported for integrations that need to construct or inspect intents directly.

```js
import { buildIntent, buildSigningMessage, randomNonce, canonicalize } from 'kxco-pq-chain'

// Build the canonical UTF-8 signing message for a relay intent
const msg = buildSigningMessage(operation, institutionKid, nonce, timestamp, payload)

// Build and sign a complete relay intent object ready to POST
const intent = await buildIntent({ operation, institutionKid, payload, identity })

// Generate a cryptographically random 64-hex-char nonce
const nonce = randomNonce()

// RFC 8785 JSON Canonicalization Scheme
const canonical = canonicalize({ b: 2, a: 1 })  // '{"a":1,"b":2}'
```

---

## Where this fits

A relay client, deliberately narrow: sign an intent, hand it over, get a
transaction back.

**Your institution never touches a wallet, holds ARMR, or runs a node.** KXCO
pays the gas and submits. That is the design.

**Reading chain state** — point `ethers.js` at `https://chain.kxco.ai/rpc`.
Armature L1 is public, so confirming a write needs neither this package nor us.

- [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) for the ML-DSA-65 primitives
- [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) for issued and managed identity

## Part of the KXCO stack

| Package | Purpose |
|---|---|
| `kxco-post-quantum` | ML-DSA-65 key generation, signing, and verification (FIPS 204) |
| `kxco-pq-sdk` | KxcoIdentity — issued and managed identity with on-device signing |
| `kxco-pq-chain` | This package — HTTP client for the KXCO relay |

The relay is live at `https://relay.kxco.ai`. Armature L1 RPC is at `https://chain.kxco.ai/rpc`.

---

## License

Apache-2.0 — Copyright 2026 KXCO by Knightsbridge

Authors: Shayne Heffernan and John Heffernan
