# The verified path

How an institution writes to Armature L1 now that the chain checks the
signature itself.

`RELAY.md` describes the v1 contract, where the relay verified your signature
and then wrote under its own authority. On a chain that has completed the
cutover that path is closed: a well-formed v1 intent reaches the point of
writing and is answered `410 USE_VERIFIED_PATH` without a transaction being
sent. (A malformed one still fails its own validation first, so do not read a
`400` as the path being alive.) This document is what replaced it.

The difference is who is the authority. On v1 the block recorded that the relay
wrote something. Here your public key and signature travel with the call, every
validator verifies them through the ML-DSA-65 precompile as part of block
validation, and the block records that **you** authorised it. Anyone who syncs
the chain re-executes that check, so a counterparty confirms your anchor from
chain data without an API key and without asking us.

This path verifies **ML-DSA-65** through the precompile at 0x0b, and
**ML-DSA-87** as well where the relay's verifier is PQVerifyingRelayV2 and the
chain's ML-DSA-87 precompile is active. `GET /intents/v2/params` says which:
`algorithms` lists the sets you may sign with now. An ML-DSA-87 identity comes
here only when `algorithms` includes `ML-DSA-87`; otherwise `KxcoChain` sends
its intents to the relay as v1.1 (see `RELAY.md`), where the relay verifies
them off-chain.

---

## Whose chain this is

The endpoints in this document, `relay.kxco.ai` and `chain.kxco.ai`, are KXCO's
reference deployment. They are what you point at to evaluate the stack, and
what a customer on the hosted service uses.

A deployed instance is yours. Armature L1 is software you run: your validator
set, chosen and contracted by you, on infrastructure you or your nominated
operators control, with your own relay in front of it. KXCO builds and licenses
it; KXCO does not have to be in the path.

That is the reason the verification is a consensus rule rather than a service
check. **A protocol rule holds whoever runs the validators.** Every node that
syncs re-executes the ML-DSA-65 verification and rejects a block whose
signature does not verify, so the guarantee this document describes is a
property of the software, not of who is hosting it. Nothing here changes when
the operator changes: the same client, the same three calls, the same bytes
signed, pointed at your own relay.

Where you see `relay.kxco.ai` below, read "your relay". The client takes the
URL as configuration.

---

## You may already be done

`kxco-pq-chain` 2.1 and later take this path automatically wherever the relay
offers it, and fall back to v1 where it does not. If you use `KxcoChain`, the
migration is:

```bash
npm install kxco-pq-chain@^2.1.1
```

Two things it needs from you:

- **Your public key.** It travels with the call so the chain can bind it to
  your registry record. Taken from `identity.publicKeyHex` or
  `identity.publicKey` when present; otherwise pass `publicKeyHex` to the
  constructor. If it is missing the client says so **before** sending, because
  a write that fails on-chain for a missing key looks identical to one that
  failed for a wrong key.
- **Nothing else.** The sequential nonce is read for you.

```js
const chain = new KxcoChain({
  relay: 'https://relay.kxco.ai',
  identity,                      // { kid, sign(), publicKeyHex }
  licenceKey: process.env.KXCO_LICENCE_KEY,
})
await chain.anchorAttestation({ payloadHash, purpose: 'quarterly-report' })
```

The rest of this document is for anyone implementing the wire format directly.

---

## Before your first write: be a registered institution

v1 let any key id anchor an attestation, because the registry did not check.
The verifying relay does: an unregistered key id is rejected with
`UNKNOWN_INSTITUTION` before anything else happens.

Registration is an onboarding step KXCO performs, and it carries **proof of
possession**: the signature is produced by the very key being registered, over
the message the contract reconstructs, so registering a key you do not hold is
not something the call can express.

Check your own status at any time:

```bash
curl -s https://chain.kxco.ai/kids/<your-kid>
```

---

## The three calls

### 1. Where to send, and what chain

```
GET /intents/v2/params
```

```json
{ "ok": true,
  "verifyingRelay": "0xB94E0829046B7c50db51C5eC4F6F4C8B3d7fb2F5",
  "chainId": 1111111,
  "legacyRelay": "0x0000000000000000000000000000000000000000",
  "algorithms": ["ML-DSA-65"] }
```

`verifyingRelay` is the one value you cannot derive, and it goes inside the
signed message. A `503` here means this relay has not cut over; use v1.

**Do not hold `verifyingRelay` for the life of a process.** The registry can be
pointed at a new verifier, and a message signed for the old address is refused
`BAD_SIGNATURE`. Read it again at least every five minutes, and once more after
a `BAD_SIGNATURE` or `BAD_NONCE`, before retrying a single time. `kxco-pq-chain`
does both from 2.3.1; 2.1.x to 2.3.0 kept it per client for good.

`algorithms` lists the ML-DSA parameter sets the chain verifies on this path at
the current block. `pendingAlgorithms`, when present, lists sets the verifier
checks that the chain has not switched on yet. A relay that predates the field
verifies ML-DSA-65 only.

Everything else you compute yourself. The operation tags are
`keccak256("<operationName>")`, so **you never trust a relay to tell you what
you are about to sign**. `kxco-pq-chain` exports them as `OPERATION_TAGS`, and
`fetchOperationTags()` reads them back off the contract if you want the drift
check.

### 2. Your next nonce

```
GET /intents/v2/nonce/<kid>        ->  { "ok": true, "kid": "…", "nonce": 7 }
```

Sequential, per key, consumed on success, and held by the contract rather than
by the relay. A signature names one nonce and is worthless at any other, which
is what makes a replay impossible rather than merely detected.

Read it immediately before signing. If two of your processes sign concurrently
one of them gets `409 BAD_NONCE`; re-read and re-sign rather than retrying the
same bytes.

A chain that cannot be reached returns `503`, never a nonce. Zero is a real
nonce, and returning it on failure would have you sign for one the contract
passed long ago.

### 3. The write

```
POST /intents/v2
Content-Type: application/json
Authorization: Bearer <licenceKey>
```

```json
{ "operation":      "anchorAttestation",
  "institutionKid": "1c766d9e2801db23",
  "publicKeyHex":   "<3904 hex chars: your ML-DSA-65 public key>",
  "signature":      "<6618 hex chars>",
  "nonce":          7,
  "payload":        { "payloadHash": "0x…", "purpose": "quarterly-report" } }
```

Success carries the transaction, the chain it landed on, and the fact that the
chain checked it:

```json
{ "ok": true, "txHash": "0x…", "blockNumber": 3554863,
  "chainId": 1111111, "verifiedOnChain": true }
```

---

## What you sign

Not a JSON string. The exact bytes the contract rebuilds, ABI-encoded:

```
abi.encode(
  address  verifyingRelay,     // from /intents/v2/params
  uint256  chainId,            // 1111111
  bytes32  operationTag,       // keccak256("anchorAttestation")
  bytes8   kid,                // your 16-hex key id
  uint64   nonce               // from /intents/v2/nonce/:kid
) ‖ abi.encode(<the operation's arguments, in order>)
```

An **ML-DSA-87** key signs the same prefix with one more word after the nonce,
`bytes32 keccak256("ML-DSA-87")`, so the algorithm is inside the signature. A
rotation is signed by the old key and the new key over one message: the prefix
follows the old key, and the arguments end with the same tag when the new key
is ML-DSA-87. The contract decides the set from the length of the key you send
(1952 bytes ML-DSA-65, 2592 bytes ML-DSA-87), never from a field you set. Send
`"alg": "ML-DSA-87"` in the body as well, so the relay can refuse a mismatch
before any gas is spent. `authorisingMessage({ ..., alg: 'ML-DSA-87' })` builds
it, and the contract's `authorisingMessageFor(algorithmTag, ...)` returns it.

Every element is inside the signature. Change the chain, the contract, the
operation, the key id, the nonce or **any argument** and it stops verifying.
That is the property v1 lacked: an early iteration signed a message bound to
nothing, so one signature would have authorised any transfer to any recipient
for any amount, repeatedly.

Build it with `authorisingMessage()` from `kxco-pq-chain`, and the arguments
with `INTENT_V2_ARGS[operation](...)`. If you encode it yourself, check it
against the contract, which will tell you what it expects:

```solidity
relay.authorisingMessage(operationTag, kid, nonce, abi.encode(args))
```

Compare byte for byte. An encoder mismatch is indistinguishable from a wrong
key once it reaches the chain, so it is worth one call to rule out.

---

## Failures, and what each one means

| Status | Code | What happened |
|---|---|---|
| 400 | `INVALID_INTENT` | A required field is missing. Nothing was sent. |
| 400 | `MISSING_NONCE` | The nonce was absent or not an integer. v2 needs the sequential one, not a random value. |
| 400 | `UNKNOWN_OPERATION` | Not one of the eight operations. Nothing was sent. |
| 400 | `BAD_KID` | A key id that is not 16 hex characters, rejected before the chain is asked. |
| 400 | `UNSUPPORTED_ALG` | `alg` is not `ML-DSA-65` or `ML-DSA-87`. Nothing was sent. |
| 400 | `ALG_NOT_VERIFIED_ON_CHAIN` | An ML-DSA-87 intent where the verifier checks ML-DSA-65 only. Use v1.1 at `POST /intents`. |
| 400 | `UNSUPPORTED_PUBLIC_KEY` | The key is neither 1952 nor 2592 bytes. |
| 403 | `ALG_MISMATCH` | `alg` is not the set of the key you sent. Nothing was sent. |
| 403 | `UNKNOWN_INSTITUTION` | The chain has no active record for this key id. |
| 403 | `PUBLIC_KEY_MISMATCH` | The key you sent is not the one registered for this key id. |
| 403 | `BAD_SIGNATURE` | The chain rejected the signature. Usually the message, not the key: check your encoder against `authorisingMessage()` first. |
| 409 | `BAD_NONCE` | Not the next nonce. Re-read and re-sign. |
| 410 | `USE_VERIFIED_PATH` | A valid v1 intent sent to `POST /intents` on a chain that has cut over. Refused before any gas is spent. |
| 503 | `VERIFIED_PATH_UNAVAILABLE` | This relay has not cut over. Use v1. |
| 503 | `ALG_NOT_ACTIVE_ON_CHAIN` | The verifier checks ML-DSA-87 but the chain has not switched it on yet. Nothing was sent; retry once `algorithms` lists it. |
| 503 | `CHAIN_UNAVAILABLE` | The chain could not be read. Nothing was attempted. |

`BAD_SIGNATURE` is the one worth dwelling on, because three different mistakes
land here: a wrong key, a wrong message, and a wrong argument encoding. The
contract cannot tell them apart and neither can we. Compare your bytes against
`authorisingMessage()` before assuming the key is at fault.

---

## Checking it yourself

Nothing here asks you to take our word.

```bash
# every registry write is verified in consensus
curl -s https://relay.kxco.ai/health

# the anchor, from the chain, with no KXCO service in the path
curl -s -X POST https://chain.kxco.ai/rpc -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionReceipt","params":["0x…"]}'

# the attestation, offline, no network
npx kxco-verify --file attestation.json
```

A verified write costs roughly 290,000 gas against roughly 107,000 unverified.
The difference is the ML-DSA-65 verification plus the calldata for a 1,952-byte
public key and a 3,309-byte signature. KXCO pays it; you never hold ARMR.
