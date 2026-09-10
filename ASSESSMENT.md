# Assessment notes

The answers a buyer's readiness assessment asks for: what this package does,
how it moves when algorithms move, and what it takes to run it.

Algorithm conformance belongs to
[`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum), which
runs 2,103 NIST ACVP vectors and a cross-implementation interoperability matrix
and publishes the lot. Cited here, proven there.

## What this package is

The client that turns an institution's decision into a fact on Armature L1.
Build an intent, sign it with ML-DSA-65, POST it to the relay, and every
validator checks that signature as a protocol rule before the transaction is
included.

**The signature is verified in consensus, not by a service.** This is the claim
worth assessing. The relay submits the transaction and pays for it, and it
cannot manufacture an institution's intent: the signature is checked against the
institution's public key registered on chain, by every validator, as a rule of
the protocol. A compromised or hostile relay could refuse, delay or reorder
submissions. It could not sign as you. So the trust placed in KXCO here is
availability and ordering, and authenticity rests on the chain.

**No token, no node, no RPC endpoint.** The institution never holds ARMR, never
runs infrastructure and is billed monthly by invoice. A post-quantum on-chain
record without a treasury operation attached to it is the difference between
this being a project and being a line item.

**Replay is handled at the protocol.** The relay checks a nonce before
submission, so a captured intent cannot be resubmitted.

**`chainId` is asserted, not decorative.** A response naming another chain
throws `WRONG_CHAIN`; a response with no chain id throws `MISSING_CHAIN_ID`.
The client refuses a wrong answer rather than recording it.

**The operations are the institutional lifecycle**, not a generic write:
register an institution, issue and revoke credentials, revoke a key outright,
rotate a key, anchor an audit root, anchor an attestation hash, register an
agent. `revokeKid` is what a registry lookup reads when it answers `revoked`,
which is the operation that makes `anchored+live` verification start refusing
envelopes signed by that key.

## Scope

This package signs and submits. Armature L1 verifies and records. The relay
carries the transaction and the cost.

Each of those is assessed where it lives, and the division is what keeps this
client small enough to read in an afternoon: nothing in `src/` holds a key
longer than a call, keeps state between calls, or decides policy.

For a buyer, the relay is a service dependency worth putting in a continuity
plan alongside its billing relationship. The security consequence is bounded and
worth stating precisely: an unavailable relay stops intents landing, and cannot
cause a wrong one to land.

## Agility

**Inherited.** Signing primitives belong to `kxco-post-quantum`.

**Coordinated, because a chain is a set of relying parties.** Armature L1 signs
at Category 3 with ML-DSA-65 from block 0, so changing what this client signs
with is a chain-level change: the relay must accept it and validators must
verify it as a protocol rule. That ordering is correct rather than
inconvenient — an intent nobody can verify is worse than one that waits — and
it is the interoperable-transition problem in its most literal form, where every
validator is a relying party and the chain is the coordination mechanism.

## Running it

**Release integrity.** Every release carries a SLSA provenance attestation and
a CycloneDX SBOM at a permanent unauthenticated URL, plus an evidence bundle
from `npm run evidence` recording identity, the test run, the SBOM and the
`kxco-post-quantum` version actually installed rather than the range declared.
`@noble/hashes` is pinned exactly.

**Supported versions.** One line moving forward. Fixes land in the next release.

**Cost.** No hardware or runtime ceiling. Signing an intent is one ML-DSA-65
operation and is never the bottleneck; the pace is the relay's and the chain's
block time.

**Connection.** `relay.kxco.ai`, which negotiates the hybrid key exchange group
`X25519MLKEM768` under TLS 1.3. Measured 7 September 2026 with OpenSSL 3.5.6,
and reproducible:

```
echo | openssl s_client -connect relay.kxco.ai:443 -servername relay.kxco.ai \
  -groups X25519MLKEM768 -tls1_3 2>&1 | grep "Negotiated TLS1.3 group"
```

The intent is signed before it is sent and verified in consensus after it
arrives, so the transport carries it rather than securing it. The security of an
intent does not rest on the connection, which is the right place for it not to
rest.

**The server contract is published.** `RELAY.md` is the full specification, so
the far end of this client is documented rather than implied.

## Correcting this document

Every claim here is checkable against `src/` and `RELAY.md`. The TLS measurement
is reproducible with the command given. If one does not match, that is a defect
worth reporting through the repository's issues.
