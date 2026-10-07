# kxco-pq-chain

**Post-quantum records on Armature L1 with no wallet, no token and no node: every validator verifies your ML-DSA-87 or ML-DSA-65 signature in consensus.**

[![npm](https://img.shields.io/npm/v/kxco-pq-chain?label=npm&color=b0964f)](https://www.npmjs.com/package/kxco-pq-chain)
[![downloads](https://img.shields.io/npm/dm/kxco-pq-chain?label=downloads&color=b0964f)](https://www.npmjs.com/package/kxco-pq-chain)
[![NIST ACVP](https://img.shields.io/badge/NIST_ACVP-1,793_passed,_0_failed-2ea44f)](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md)
[![npm provenance](https://img.shields.io/badge/npm-provenance-2ea44f)](https://www.npmjs.com/package/kxco-pq-chain)
[![Socket](https://socket.dev/api/badge/npm/package/kxco-pq-chain)](https://socket.dev/npm/package/kxco-pq-chain)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)
[![node](https://img.shields.io/node/v/kxco-pq-chain.svg)](https://nodejs.org)
[![CI](https://github.com/KnightsbridgeAIQ/kxco-pq-chain/actions/workflows/ci.yml/badge.svg)](https://github.com/KnightsbridgeAIQ/kxco-pq-chain/actions/workflows/ci.yml)

Institutions sign ML-DSA-87 or ML-DSA-65 intents with their existing post-quantum key, POST them to the KXCO relay at `https://relay.kxco.ai`, and receive a transaction hash. KXCO validates the signature, pays gas in ARMR, and submits the EVM transaction on Armature L1. No wallets, no gas, no Ethereum node required.

- **Verified in consensus.** Your public key and signature travel with the call, and every validator checks them through the ML-DSA-87 or ML-DSA-65 precompile as a protocol rule, so the block records that your institution authorised the write, per [VERIFIED-PATH.md](./VERIFIED-PATH.md).
- **Confirmed from chain data.** Anyone who syncs Armature L1 re-executes that check, so a counterparty confirms your anchor with no API key and no call to KXCO.
- **No wallet, no token, no node.** KXCO's relay pays the gas and submits the transaction, and your institution is invoiced: it never holds ARMR, sets a gas price or configures an RPC endpoint.
- **Licensed from the first line.** The client checks for your licence key when it is constructed, so a missing key surfaces at deploy time rather than on a customer's first credential, and a relay on `localhost` needs none for development and CI.
- **Every element signed, every answer checked.** The verifying contract, chain, operation, key id, a sequential on-chain nonce and every argument sit inside the signature, and by default the client refuses any relay response that does not name Armature L1.
- **Proven underneath.** 1,793 NIST ACVP vectors passed, 0 failed, and 225 interoperability checks against liboqs, Bouncy Castle and the Python reference implementations, 0 failed, in [`kxco-post-quantum`](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md).
- **A supply chain you can check.** SLSA provenance and a CycloneDX SBOM on every release since 1.1.5, third-party dependencies pinned to exact versions, and every GitHub Action pinned by commit SHA.

**The migration has dates.**

- **NIST** published [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final), [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) and [FIPS 205](https://csrc.nist.gov/pubs/fips/205/final) in August 2024.
- **United States:** [Executive Order 14412](https://www.federalregister.gov/documents/2026/06/25/2026-12909/securing-the-nation-against-advanced-cryptographic-attacks), signed on 22 June 2026, moves federal high-value and high-impact systems to post-quantum key establishment by 31 December 2030 and to post-quantum signatures by 31 December 2031. [OMB M-26-15](https://www.whitehouse.gov/wp-content/uploads/2026/06/M-26-15-Execution-of-the-Migration-to-Post-Quantum-Cryptography.pdf) requires PQC-agile libraries for all new applications.
- **United Kingdom:** the [NCSC](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines) sets 2028, 2031 and 2035 as its migration milestones.

[Quick start](#quick-start) · [How it works](#how-it-works) · [For institutions](#for-institutions) · [Verified path](./VERIFIED-PATH.md) · [Assessment notes](./ASSESSMENT.md) · [Changelog](./CHANGELOG.md) · [kxco.ai](https://kxco.ai)

## Armature L1 at a glance

| | |
|---|---|
| Network | Armature L1, a permissioned, EVM-compatible settlement layer |
| Chain ID | 1111111 |
| Consensus | QBFT PoA, instant finality (~2 s target block time) |
| PQ verification | On-chain ML-DSA-87 at precompile `0x4b58434f00000000000000000000000000000087` and ML-DSA-65 at `0x0b` (NIST FIPS 204) |
| Token | ARMR, with gas paid by the KXCO relay, so clients hold no crypto |
| Explorer & docs | [chain.kxco.ai](https://chain.kxco.ai) |

---

## When to use this

Any institution backend that needs on-chain credential management (registering identities, issuing and revoking credentials, anchoring audit roots, rotating keys) without running an Ethereum node or holding crypto. If you already have a `KxcoIdentity` from `kxco-pq-sdk`, this is the only client you need to write to the chain.

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

// identity is a KxcoIdentity from kxco-pq-sdk (it exposes .kid, .sign() and .publicKeyHex)
const chain = new KxcoChain({
  identity:   institutionIdentity,
  licenceKey: process.env.KXCO_LICENCE_KEY,  // or set the env var and omit this
  // relay defaults to https://relay.kxco.ai
  timeout:    10_000,                        // optional, ms, default 10 000
})

// Register the institution on-chain, once, during onboarding
const { txHash, blockNumber } = await chain.registerInstitution({
  publicKeyHex: institutionIdentity.publicKeyHex,
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

Writes to the hosted relay run under your **licence key**. The constructor checks for it at boot, not at the first write, so a missing key throws `LICENCE_REQUIRED` at deploy time rather than on a customer's first credential. A relay on `localhost` needs no licence, so local development and CI run as they are.

---

## How it works

Your backend constructs an intent describing the operation (register, issue, revoke, anchor, rotate). The client reads the verifying relay's address and your next on-chain nonce, signs the exact bytes the contract rebuilds with your ML-DSA-87 or ML-DSA-65 private key, and POSTs the intent with your public key to `https://relay.kxco.ai/intents/v2`. Every Armature L1 validator checks that signature through the ML-DSA-87 or ML-DSA-65 precompile during block validation, so the block records that your institution authorised the write. The relay returns the `txHash` and `blockNumber` once the transaction is included. Your institution never holds ARMR, never configures an RPC endpoint, and is billed monthly via invoice.

The client takes this path automatically wherever the relay offers it, and speaks the v1 contract in [RELAY.md](./RELAY.md) to a relay that predates it. The wire format is in [VERIFIED-PATH.md](./VERIFIED-PATH.md).

---

## For institutions

The cryptography is free under Apache-2.0, works offline and needs nothing from
KXCO, now or in ten years. What KXCO sells is the part that has to be operated:
an answer about the present.

| Service | What you get |
|---|---|
| Hosted key registry | Whether a key is active, revoked or rotated, answered at verification time |
| Meta-transaction relay | KXCO validates your signed intent, pays the gas and submits it, so you never hold a token or run a node |
| On-chain anchoring | A timestamp on Armature L1 that the chain itself has verified |
| Live revocation | `anchored+live` verification, which confirms the signing key is still trusted now |
| Support and SLA | Availability commitments, an escalation path and a named contact |

Priced in USD, per seat, per year. No tokens, no nodes and no wallets. The line
between free and paid is set out in
[LICENCE-PRODUCT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/LICENCE-PRODUCT.md).

**Talk to us: [admin@kxco.ai](mailto:admin@kxco.ai)** · [kxco.ai](https://kxco.ai)

---

## API

All methods are on your `KxcoChain` client and return `Promise<{ txHash: string, blockNumber: number, chainId: 1111111 }>`.

`chainId` is asserted on every response: a response naming another chain throws `WRONG_CHAIN`, and a response with no chain id throws `MISSING_CHAIN_ID`. The server contract is in [`VERIFIED-PATH.md`](VERIFIED-PATH.md), with the v1 contract in [`RELAY.md`](RELAY.md).

### `new KxcoChain(opts)`

| Parameter | Type | Required | Description |
|---|---|---|---|
| `opts.identity` | `{ kid: string; sign(msg: Uint8Array): Promise<Uint8Array> }` | yes | `KxcoIdentity` from `kxco-pq-sdk`, or any object with `.kid`, `.sign()` and `.publicKeyHex` |
| `opts.publicKeyHex` | `string` | no | Hex ML-DSA-87 or ML-DSA-65 public key sent with each write so the chain can bind it to your registry record. Read from `identity.publicKeyHex` or `identity.publicKey` when omitted. Its length decides the set this client signs with |
| `opts.alg` | `'ML-DSA-87' \| 'ML-DSA-65'` | no | The identity's parameter set, for an identity that does not expose its public key. Where the key is known its length decides, and a value that disagrees throws `BAD_CONFIG`. With neither, the client sends v1 intents, which mean ML-DSA-65, so an identity from before this option works unchanged. An ML-DSA-87 identity that hides its key passes `'ML-DSA-87'` |
| `opts.relay` | `string` | no | Relay base URL. Default: `'https://relay.kxco.ai'` |
| `opts.licenceKey` | `string` | for a hosted relay | Falls back to `KXCO_LICENCE_KEY` / `KXCO_LICENSE_KEY`. Missing throws at construction |
| `opts.licenceHeader` | `'authorization' \| 'x-kxco-licence'` | no | Which header carries it. Default `'authorization'`, as a Bearer token |
| `opts.requireLicence` | `boolean` | no | Overrides the loopback heuristic in both directions |
| `opts.strictChainId` | `boolean` | no | Require `chainId` in every response. Default `true` |
| `opts.timeout` | `number` | no | Request timeout in ms. Default: `10000` |
| `opts.onUsageEvent` | `(event) => void` | no | Structured record per write, for your own observability. Off by default |

Read-only: `chain.relay`, `chain.licensed` and `chain.alg`, the parameter set this client signs with. The licence key itself is never exposed.

---

### `chain.registerInstitution({ publicKeyHex, metadataUrl? })`

Register an institution on-chain. Called once during onboarding.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `publicKeyHex` | `string` | yes | Hex-encoded public key: 2592 bytes for ML-DSA-87, 1952 for ML-DSA-65 |
| `metadataUrl` | `string` | no | URL of institution metadata JSON |

---

### `chain.issueCredential({ userKid, userPublicKeyHex, role, expiresAt? })`

Record a user credential issuance on-chain.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `userKid` | `string` | yes | 16-hex-char kid of the issued user |
| `userPublicKeyHex` | `string` | yes | Hex-encoded user ML-DSA-87 or ML-DSA-65 public key |
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

New wire operation in 2.0.0. Confirm your relay offers it before shipping code that calls it: the client reports `UNKNOWN_OPERATION` from a relay that does not.

---

### `chain.anchorHash({ hash, purpose? })`

Anchor any hex SHA-256 digest on-chain. The general form of `anchorAuditRoot` and `anchorAttestation`, which keep their own on-chain semantics.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `hash` | `string` | yes | Hex SHA-256 digest (64 hex chars) |
| `purpose` | `string` | no | Purpose string, e.g. `'quarterly-report'` |

New wire operation in 2.0.0, so confirm your relay offers it in the same way.

---

### `chain.registerIdentity(...)` and `chain.registerAgent(...)`

Names over the existing `registerInstitution` and `issueAgentCredential` wire operations, so the rest of the stack can use one vocabulary. Identical arguments, identical bytes on the wire.

---

### `chain.rotateKey({ newKid, newPublicKeyHex, newIdentity? })`

Record an institution key rotation on-chain. Either key may be ML-DSA-87 or ML-DSA-65, which is how an ML-DSA-65 institution moves to ML-DSA-87.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `newKid` | `string` | yes | New 16-hex-char kid after rotation |
| `newPublicKeyHex` | `string` | yes | Hex-encoded new ML-DSA-87 or ML-DSA-65 public key |
| `newIdentity` | `{ sign(msg: Uint8Array): Promise<Uint8Array>; publicKeyHex?: string; publicKey?: Uint8Array }` | on the verified path | The holder of the new key. It signs the same bytes as this identity, to prove possession. Missing throws `NEW_KEY_SIGNER_REQUIRED` before anything is sent. Not used on v1 |

---

### `chain.issueAgentCredential({ agentKid, agentPublicKeyHex, agentType, scopeHash, expiresAt })`

Register an AI agent or machine identity on-chain. Called by the sponsoring institution.

| Parameter | Type | Required | Description |
|---|---|---|---|
| `agentKid` | `string` | yes | 16-hex-char kid of the agent |
| `agentPublicKeyHex` | `string` | yes | Hex-encoded agent ML-DSA-87 or ML-DSA-65 public key |
| `agentType` | `'llm' \| 'robot' \| 'iot' \| 'process'` | yes | Agent category |
| `scopeHash` | `string` | yes | Hex SHA-256 of the canonical scope JSON |
| `expiresAt` | `number` | yes | Unix seconds. Mandatory, and greater than 0 |

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

## The KXCO post-quantum family

This turns a signed decision into a record on Armature L1. The rest of the family covers the jobs around it:

| You need to | Install |
|---|---|
| Put the whole stack in one install | [`kxco-pq`](https://www.npmjs.com/package/kxco-pq) |
| Use ML-DSA, ML-KEM and SLH-DSA directly | [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) |
| Keep signing keys on the HSM you already run | [`kxco-pq-hsm`](https://www.npmjs.com/package/kxco-pq-hsm) |
| Sign a document or record anyone can verify offline | [`kxco-pq-attest`](https://www.npmjs.com/package/kxco-pq-attest) |
| Keep a tamper-evident audit trail | [`kxco-pq-audit`](https://www.npmjs.com/package/kxco-pq-audit) |
| Verify a signature in a browser, with no server | [`kxco-verify`](https://www.npmjs.com/package/kxco-verify) |
| Issue institution identity credentials | [`kxco-pq-sdk`](https://www.npmjs.com/package/kxco-pq-sdk) |
| Encrypt files and payloads to one or many recipients | [`kxco-pq-vault`](https://www.npmjs.com/package/kxco-pq-vault) |
| Encrypt Node streams and WebSockets | [`kxco-pq-tls`](https://www.npmjs.com/package/kxco-pq-tls) |
| Sign and verify webhooks | [`kxco-post-quantum-webhook`](https://www.npmjs.com/package/kxco-post-quantum-webhook) |
| Give an AI agent an identity a verified institution sponsors | [`kxco-pq-agent`](https://www.npmjs.com/package/kxco-pq-agent) |
| Have Armature L1 verify a signature in consensus | [`kxco-pq-chain`](https://www.npmjs.com/package/kxco-pq-chain) |
| Prove an envelope at three levels, offline to on-chain | [`kxco-pq-network`](https://www.npmjs.com/package/kxco-pq-network) |
| Generate and rotate keys from a terminal | [`kxco-pq-cli`](https://www.npmjs.com/package/kxco-pq-cli) |
| Find quantum-vulnerable cryptography in a dependency tree | [`kxco-pq-scan`](https://www.npmjs.com/package/kxco-pq-scan) |
| Fail the build when code reaches past the wrapper | [`eslint-plugin-kxco-pq`](https://www.npmjs.com/package/eslint-plugin-kxco-pq) |

## Release integrity

Every release since 1.1.5 carries a SLSA provenance attestation tying the published tarball to
the commit and workflow that built it: verify with `npm audit signatures`, or read
it from `registry.npmjs.org/-/npm/v1/attestations/kxco-pq-chain@<version>`. A CycloneDX
SBOM is published, from v1.1.5, as a GitHub Release asset at
`releases/download/v<version>/sbom.cyclonedx.json`, a permanent unauthenticated
URL. Sibling `kxco-*` packages sit on caret ranges so a correctness fix in the
base package reaches you on the next install, with no release of every package
above it.

## Security

Intents are signed with **ML-DSA-87** or **ML-DSA-65** (NIST FIPS 204) via [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), running on the OpenSSL 3.5 primitives where the runtime provides them, and Armature L1 checks each signature in consensus. No custom cryptography.

Evidenced, and reproducible on your own machine:

- **1,793 NIST ACVP vectors passed, 0 failed** across FIPS 203, 204 and 205, pinned by digest, per [CONFORMANCE.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/CONFORMANCE.md). The other 310 are pairings the library refuses as weaker than the parameter set
- **225 interoperability checks passed, 0 failed**, against OpenSSL 3.5, liboqs, Bouncy Castle and dilithium-py/kyber-py, in both directions
- **SLSA provenance** on every release since 1.1.5: verify with `npm audit signatures`
- **CycloneDX SBOM** published with every release since 1.1.5
- `npm run evidence` records this package's identity, its own test run, its SBOM and the `kxco-post-quantum` version actually installed

Dependency audit history is recorded in [AUDIT.md](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/blob/main/AUDIT.md).

On the verified path the signature covers the verifying contract, the chain id, the operation, the key id, a sequential on-chain nonce and every argument, so an intent cannot be replayed, sent to another chain or given different arguments and still verify. The licence key is never readable from the client, and a usage event carries only its first 8 characters.

To report a vulnerability, email **security@kxco.ai**.

## License

Apache-2.0 © 2026 Knightsbridge Financial Ltd, trading as KXCO. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

## Maintainers

Shayne Heffernan and John Heffernan, [KXCO by Knightsbridge](https://kxco.ai)
