# Relay server contract

What `kxco-pq-chain` 2.x sends, and what a relay must do with it.

This document describes the contract the **client** implements and enforces. It is written so the hosted relay at `https://relay.kxco.ai` and any self-hosted relay can be checked against one specification, and so a customer can reason about failures without reading our server code.

Where this document and a deployed relay disagree, the disagreement is a bug in one of them. It is not a licence to guess.

---

## Endpoint

```
POST /intents
Content-Type: application/json
Authorization: Bearer <licenceKey>        # or: X-KXCO-Licence: <licenceKey>
```

One endpoint, one method. The operation is in the body, not the path, because the signature covers the operation name and a path-based router would let a proxy rewrite it.

---

## Request body

```json
{
  "operation":      "anchorHash",
  "institutionKid": "aa29f37ab7f4b2cf",
  "nonce":          "<64 random hex chars>",
  "timestamp":      1756857600,
  "payload":        { "hash": "…", "purpose": "quarterly-report" },
  "signature":      "<6618 hex chars: ML-DSA-65 over the signing message>"
}
```

No other top-level fields are ever sent. In particular there is **no** gas price, gas limit, wallet address, `from`, private key or ARMR anywhere in an intent — the client's test suite asserts this on every operation. An institution never holds ARMR and never runs a node.

### Signing message

Newline-delimited UTF-8. The relay must reconstruct it exactly:

```
kxco-relay-v1
operation: <name>
institutionKid: <16-hex kid>
nonce: <64 hex>
timestamp: <unix seconds>
payload: <RFC 8785 JCS canonical JSON of the payload object>
```

The payload is canonicalised with JCS (`canonicalize()` in `src/jcs.js`) so key order in the JSON body cannot change what was signed.

---

## What the relay MUST reject

A relay that accepts any of these is not implementing this contract.

| Condition | Status | `code` |
|---|---|---|
| Missing or malformed licence | `401` | `LICENCE_REQUIRED` |
| Licence valid but not entitled to this operation | `403` | `LICENCE_SCOPE` |
| Licence expired or over quota | `403` | `LICENCE_EXHAUSTED` |
| `signature` does not verify under the registered public key for `institutionKid` | `401` | `BAD_SIGNATURE` |
| `institutionKid` not registered on Armature L1 | `403` | `UNREGISTERED_IDENTITY` |
| `institutionKid` revoked or rotated out | `403` | `KID_REVOKED` / `KID_ROTATED` |
| `nonce` already seen | `409` | `REPLAY` |
| `timestamp` outside ±5 minutes of server time | `400` | `STALE_TIMESTAMP` |
| `operation` not in the table below | `400` | `UNKNOWN_OPERATION` |
| Payload fails that operation's schema | `400` | `BAD_PAYLOAD` |

The client turns `401` and `403` into `KxcoChainError` with code `LICENCE_REJECTED` when the relay supplies no `code` of its own, so supplying one is worth doing.

**Unsigned, unregistered and unlicensed are three separate rejections.** A relay that collapses them into one status makes it impossible for a customer to tell "my key is wrong" from "my subscription lapsed".

---

## Response

### Success

```json
{
  "ok":          true,
  "txHash":      "0x…64 hex…",
  "blockNumber": 90633,
  "chainId":     1111111
}
```

**`chainId` is required.** The client rejects a response without it (`MISSING_CHAIN_ID`) and rejects a response naming any other chain (`WRONG_CHAIN`). A caller is about to store that transaction hash as proof that something is on Armature L1; handing back a hash from somewhere else would be worse than failing.

`strictChainId: false` relaxes the first check for a relay that predates the field. It does not relax the second — a wrong chain id always throws — and it does not invent the answer: the result then carries `chainIdConfirmed: false`, so a caller storing it as proof can tell that the relay never said.

`txHash` must be `0x` followed by 64 hex characters and `blockNumber` a non-negative integer. The client validates both and throws `BAD_RELAY_RESPONSE` otherwise, so a relay bug is named at the relay rather than surfacing later as an envelope that will not verify.

### Failure

```json
{ "ok": false, "code": "REPLAY", "error": "nonce already used" }
```

`error` is shown to the caller. `code` is what they branch on.

---

## Operations

| `operation` | Payload | Notes |
|---|---|---|
| `registerInstitution` | `{ publicKeyHex, metadataUrl }` | Also reached as `registerIdentity()`. |
| `rotateKey` | `{ newKid, newPublicKeyHex }` | Registry must then report the old kid as `rotated` with `rotatedTo`. |
| `revokeKid` | `{ kid, reason }` | **New in 2.0.0.** Revokes a key outright. Registry must then report it `revoked`. |
| `issueCredential` | `{ userKid, userPublicKeyHex, role, expiresAt }` | |
| `revokeCredential` | `{ userKid, reason }` | Revokes an issued credential, not the key itself. |
| `anchorHash` | `{ hash, purpose }` | **New in 2.0.0.** Any hex SHA-256 digest. |
| `anchorAuditRoot` | `{ rootHash, entryCount }` | |
| `anchorAttestation` | `{ payloadHash, purpose }` | |
| `issueAgentCredential` | `{ agentKid, agentPublicKeyHex, agentType, scopeHash, expiresAt }` | Also reached as `registerAgent()`. |
| `revokeAgentCredential` | `{ agentKid, reason }` | |

`registerIdentity()` and `registerAgent()` are **client method names over existing wire operations**. They send `registerInstitution` and `issueAgentCredential`. No new server work.

`revokeKid` and `anchorHash` are **new wire operations**. A relay that has not implemented them must answer `400 UNKNOWN_OPERATION`, which the client surfaces cleanly. Verify against your deployment before shipping code that calls them.

---

## Registry read side

The write path above is this package. The read side is `kxco-pq-network`:

```
GET /kids/:kid        on https://chain.kxco.ai
```

A relay write and the registry read must agree. After a successful `revokeKid`, `GET /kids/<kid>` must report `status: "revoked"` — otherwise `anchored+live` verification will keep accepting a key the chain says is dead. See the registry contract in [`kxco-pq-network`](https://www.npmjs.com/package/kxco-pq-network).

**Measured 3 September 2026, so it is not guessed at:**

| Endpoint | State |
|---|---|
| `POST https://relay.kxco.ai/intents` | **live.** An empty body returns `400 {"ok":false,"code":"INVALID_INTENT","error":"missing required fields"}`, and `GET /health` returns `{"ok":true}`. The error shape above matches what it actually sends |
| `GET https://chain.kxco.ai/kids/:kid` | **implemented, not yet deployed.** The live host still serves the marketing site's HTML 404 |

### chainId: read the relay source, not a guess

The deployed relay's `send()` returned `{ txHash, blockNumber }` and **no `chainId`**. Under this client's default `strictChainId: true`, every write would have thrown `MISSING_CHAIN_ID` the moment 2.0.0 shipped.

`kxco-relay/src/lib/chain.js` now reads the chain id from its provider at startup and includes it in every response. It is read from the network rather than hard-coded, so a relay pointed at the wrong RPC reports the chain it is really writing to; if it cannot be determined the field is omitted rather than invented.

**Both sides have to ship together.** A `kxco-pq-chain` 2.0.0 talking to a relay that predates this change fails closed on every write. If you upgrade the client first, set `strictChainId: false` until the relay is deployed — the result then carries `chainIdConfirmed: false` so nothing pretends the chain was verified.

The registry read side is implemented in `kxco-chain-live/explorer-public` and verified end to end against a scripted chain, but is likewise not deployed. Until it is, `anchored+live` fails closed against production.

---

## Local mock

`test/licence.test.js` runs a loopback relay that enforces the licence header, the chain-id requirement and the operation names. It is the executable form of this document, and the place to add a case before changing anything here.

A relay on `localhost`, `127.0.0.1` or `::1` needs no licence, so local development and CI are unaffected by the gate.
