# Assessment notes

Where this package's boundary falls, what agility it has, and what constrains
its lifecycle.

Algorithm conformance belongs to
[`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) and is
published in that package's evidence bundle. It is referenced here, never
restated.

## Boundary

**What the assessed thing is.** A client that builds an intent, signs it with
ML-DSA-65, and POSTs it to `https://relay.kxco.ai/intents`. The signing happens
here. Everything after the POST is the relay and Armature L1, and neither is
inside this package.

**The relay is a required service connection and a trusted intermediary, and
those are two separate facts.** It submits the EVM transaction, holds the ARMR
and bills monthly by invoice, so the caller never configures an RPC endpoint
and never holds the token. Convenient, and it means:

- *Availability and cost sit with us.* If the relay is down or the account is
  in arrears, intents do not land. There is no direct-to-chain path in this
  package, so there is no fallback inside it.
- *Forgery does not sit with us.* The relay cannot manufacture an institution's
  intent, because the signature is verified against the institution's public
  key registered on Armature L1 and validators check it as a protocol rule.
  What a compromised or hostile relay could do is refuse, delay or reorder
  submissions. It could not sign as you.

That distinction is the one worth carrying into an assessment. The trust placed
in KXCO here is availability and ordering, not authenticity.

**The connection is post-quantum, measured rather than assumed.**
`relay.kxco.ai` negotiates the hybrid group `X25519MLKEM768` under TLS 1.3.
Reproduce it:

```
echo | openssl s_client -connect relay.kxco.ai:443 -servername relay.kxco.ai \
  -groups X25519MLKEM768 -tls1_3 2>&1 | grep "Negotiated TLS1.3 group"
```

Measured 7 September 2026 against OpenSSL 3.5.6.

**Endpoint authentication on that connection is classical.** The certificate is
ECDSA P-384 from Let's Encrypt. No post-quantum certificate exists in the public
WebPKI, so this is the state of the art and not a gap peculiar to us. The
practical reading: an adversary recording the connection today cannot decrypt
it later, and endpoint authentication would have to be broken in real time.

It also matters less here than it would elsewhere, because the security of an
intent does not rest on the TLS connection. The intent is signed with ML-DSA-65
before it is sent and verified in consensus after it arrives, so a broken
transport could suppress or expose an intent but could not alter one.

**Enforce policy.** `chainId` is asserted, not decorative: a response naming
another chain throws `WRONG_CHAIN` and a response with no chain id throws
`MISSING_CHAIN_ID`. That is a client-side rejection of a wrong answer, and it
is the one policy control in this package.

**Retain history.** Nothing is stored here. The record is on Armature L1, and
what this package returns is a `txHash` and `blockNumber` for the caller to
keep. A caller who discards those has no local handle on the anchor.

**Start and update.** No release signing of its own. Published through CI with
npm provenance.

## Agility

**Inherited.** Signing primitives belong to `kxco-post-quantum`; see that
package's `AGILITY.md`.

**The constraint that is specific to this package: the chain has to agree.**
Everywhere else in the family a parameter-set change is a release. Here it is a
release, plus a relay that accepts the new signature, plus validators that
verify it as a protocol rule. Armature L1 signs at Category 3 with ML-DSA-65
from block 0, so changing what this client signs with is a chain-level change
and not a client-level one.

That is the correct dependency ordering and it means the client is not the
place to look for agility. It also means a migration here is coordinated rather
than unilateral, which is the interoperable-transition problem in its most
literal form: every validator is a relying party.

## Lifecycle

**Supported versions.** One line moving forward, matching the family.

**Pins.** `@noble/hashes` is declared exactly. `kxco-post-quantum` is declared
`^1.3.0`, and the tree the evidence bundle was last built from resolved it to
**1.3.0**, against a current primitives release of 1.7.2. That is the widest
gap in the family between what a package runs and what is available.
`02-primitives.json` records the resolved version.

**Ceiling.** No hardware or runtime ceiling. The constraints are the relay's
rate and the chain's block time, neither of which this package controls.
Signing an intent is one ML-DSA-65 operation and is never the bottleneck.

**Blocking dependencies, and there are two.** The upstream library, as
everywhere in this family. And the relay service with its billing relationship,
which is ours. A buyer's continuity planning needs an answer for extended relay
unavailability, and this package does not contain one.

**Roadmap.** No external audit, no bug bounty. No published availability target
for the relay, which is the number a buyer will ask for once they notice there
is no fallback path.

## Correcting this document

The TLS measurement is reproducible with the command given. Everything else is
checkable against `src/` and `RELAY.md`. If a claim does not match, that is a
defect worth reporting through the repository's issues.
