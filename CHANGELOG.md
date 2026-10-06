# Changelog

## 2.3.1
**A long-running client follows a change of verifier.** On the verified path
the signed message names the verifier contract, and the registry can move to
another verifier with one transaction (`setRelay`). Up to 2.3.0 a `KxcoChain`
instance asked the relay for that address once and kept the answer for its
whole life; the five-minute expiry of the shared cache only helped new
instances. So after a move, a process that keeps one client (a heartbeat, an
anchoring service) went on signing for the old verifier with a nonce read from
the new one, and every write was refused `BAD_SIGNATURE` until the process
restarted or the registry moved back.

- A client's own answer now expires with the shared one, five minutes after it
  was fetched.
- A verified-path write refused `BAD_SIGNATURE`, `BAD_NONCE` or
  `ALG_NOT_VERIFIED_ON_CHAIN`, each of which a stale verifier can cause, makes
  the client forget the verifier (its own answer and the process-wide one), ask
  the relay again, re-read the nonce, re-sign and send once more. Once only, and
  only for a 4xx refusal carrying no transaction hash, which the relay returns
  before it sends anything, so the refused intent's nonce was never used and at
  most one write lands. Any other refusal, a 5xx, a timeout or a lost connection
  is returned as before and never retried.
- The same the other way: v1 sent because the last answer said the verified
  path was not there for this key (before a cutover, or before ML-DSA-87
  switched on), refused `410 USE_VERIFIED_PATH` before any send, is retried once
  the same way. A client constructed with `verifiedPath: false` is not.
- A discovery probe that fails (no connection, a timeout, or a 5xx other than
  `503 VERIFIED_PATH_UNAVAILABLE`) is no longer remembered by the client. Before,
  a client whose first probe failed stayed on v1 for its whole life; now the next
  write asks again. A relay's own `503 VERIFIED_PATH_UNAVAILABLE` is still
  believed for five minutes.

When nothing changes, the only difference on the wire is one
`GET /intents/v2/params` per relay every five minutes. No API change.

## 2.3.0
**ML-DSA-87 on the verified path.** Where a relay's verifier checks ML-DSA-87
on-chain (PQVerifyingRelayV2) and `GET /intents/v2/params` lists `ML-DSA-87`
in `algorithms`, an ML-DSA-87 identity now writes through `POST /intents/v2`
like an ML-DSA-65 one. Where it is not listed, the client sends v1.1 to
`POST /intents` exactly as 2.2.0 does.

The algorithm is inside the signed bytes. An ML-DSA-87 key signs the v2
message with `keccak256("ML-DSA-87")` as a sixth prefix word, after the nonce.
A rotation's arguments carry the same tag as a third word when the NEW key is
ML-DSA-87. `authorisingMessage()` takes an optional `alg`,
`INTENT_V2_ARGS.rotateInstitutionKey()` an optional `newAlg`, and
`signIntentV2()` signs with the set its key belongs to and returns `alg`. New
export: `ALGORITHM_TAGS`.

**Rotation on the verified path.** `rotateKey()` takes `newIdentity`, the holder of the new
key, and sends its signature over the same bytes as the old key's as `newSignature`, which
the contract checks as proof of possession. Without it, on the verified path, the client
refuses with `NEW_KEY_SIGNER_REQUIRED` before anything is sent; before this, it sent an
intent the relay could not complete. A signer holding a different key, or signing with the
other set, is refused as `BAD_ARGUMENT`. This is how an ML-DSA-65 institution moves to
ML-DSA-87. A v1 rotation is unchanged.

An ML-DSA-65 identity is unchanged: same path, same bytes, no `alg` field.

## 2.2.0
**ML-DSA-87 intents.** An identity whose key is ML-DSA-87 signs a v1.1 intent:
the v1 message under a new first line, `kxco-relay-v1.1`, followed by
`alg: ML-DSA-87`, so the algorithm is inside the signed bytes. The intent body
carries `alg` as well. `buildSigningMessage()` and `buildIntent()` take an
optional `alg`; without it they produce the v1 message and intent byte for byte
as before, which means ML-DSA-65.

The key decides. `KxcoChain` reads the parameter set from the identity's public
key (1952 bytes ML-DSA-65, 2592 bytes ML-DSA-87). An `alg` option, or
`identity.alg`, is used only where no key is exposed, and one that disagrees
with the key is refused as `BAD_CONFIG`. New exports: `algForPublicKey()` and
`INTENT_ALGS`. `client.alg` reports the set in use.

An ML-DSA-87 intent never takes the verified path. The chain verifies through
the ML-DSA-65 precompile at 0x0b and has no ML-DSA-87 verifier yet, so the
client does not probe for it and sends the intent to `POST /intents`, where the
relay verifies it off-chain. An ML-DSA-65 client is unchanged: same path, same
bytes, no `alg` field.

The `kxco-post-quantum` floor is now `^1.6.0`.

## 2.1.7

canonicalize refuses an object key named `__proto__`, and buildSigningMessage
refuses a header field holding a line break or an unpaired surrogate, both as
`BAD_ARGUMENT`. The constructor refuses a relay that is not a string as
`BAD_CONFIG`. Well-formed messages are byte-identical to before. RELAY.md lists
these refusals.

## 2.1.6

Documentation. No source change.

A NOTICE file names the copyright owner, Knightsbridge Financial Ltd, trading
as KXCO, and ships in the package, so anyone who redistributes it carries the
attribution, as section 4(d) of the Apache License requires.

## 2.1.5

Documentation. No source change.

**The npm page leads with what the package proves.** The first screen now says
that every Armature L1 validator verifies an intent's ML-DSA-65 signature in
consensus, that KXCO pays the gas under your licence, the evidence underneath
and the migration dates set by NIST, Executive Order 14412, OMB M-26-15 and the
UK NCSC.

A family table maps every KXCO package to the job it does, and a new For
institutions section sets out the operated services and how to reach us. The
evidence documents are unchanged and linked from the page.

The quick start registers the institution with the `publicKeyHex` a
`KxcoIdentity` exposes, and How it works describes the verified path the client
takes against the hosted relay.

## 2.1.4

Documentation. No source change.

**ASSESSMENT.md rewritten.** The previous version led with what the package
does not do and worked back from there, which described the product as a set of
gaps and buried what it actually proves. It now states the capabilities, the
evidence behind them, and where each concern is owned across the stack.

Nothing has been softened away. Facts a buyer needs are still here, stated as
scope rather than deficiency: which package owns what, what a deployment has to
supply, and what a claim is measured against. The change is which way round they
are told.

## 2.1.3

Documentation and a dependency refresh. No source change.

**ASSESSMENT.md.** Where this package's boundary falls, what cryptographic
agility it has beyond what the primitives provide, and what constrains its
lifecycle. It references the `kxco-post-quantum` evidence rather than restating
it, because a second copy of a conformance claim invites the reader to count it
twice.

**An evidence bundle.** `npm run evidence` records identity, this package's own
tests, its SBOM, registry signature verification, and the `kxco-post-quantum`
version actually installed rather than the range declared.

**`kxco-post-quantum` refreshed to 1.7.2**, from 1.3.0 in the previous
lockfile. Within the existing range, so no declared dependency changed. Tests
pass unchanged.

## 2.1.1

Whether a relay verifies on-chain is a property of that relay, so the answer is
now cached per relay URL across clients in a process rather than rediscovered
by each one. Constructing a client per write is a fair pattern and one real
consumer does exactly that; a probe on every write doubled the request count to
learn something that could not have changed. Five minute TTL, so a relay that
cuts over later is still picked up without a restart.

A failed probe is not cached, so one transient error cannot pin every client in
the process to v1.

## 2.1.0

**The client uses on-chain verification where the relay offers it.** No code
change: upgrade the package and existing calls take the verified path.

On the v1 path the relay checks your ML-DSA-65 signature and then writes under
its own authority, so the block records that the relay wrote something. On the
verified path your public key and signature travel with the call and every
validator checks them through the ML-DSA-65 precompile as part of consensus,
so the block records that *you* authorised it.

The client asks the relay once, via `GET /intents/v2/params`, and falls back to
v1 when the answer is no. Upgrading is therefore safe against a relay on either
side of the cutover, and a relay that cuts over later is picked up by the next
process to start.

Two things a caller may need to do:

- **Provide the identity public key.** It travels with the call so the chain
  can check it against the registry record. Taken from `identity.publicKeyHex`
  or `identity.publicKey` when present; otherwise pass `publicKeyHex`. If it is
  missing the client says so before sending, rather than letting the write fail
  on-chain where it is indistinguishable from a wrong key.
- **Nothing else.** The sequential on-chain nonce is read for you.

`verifiedPath: false` pins a client to v1 while migrating.

Also added: `OPERATION_TAGS` and `OPERATION_NAMES`, the operation tags derived
locally as `keccak256("<operationName>")` rather than fetched, so a client
never has to trust a relay to tell it what it is about to sign.
`fetchOperationTags` remains, and the test suite asserts the two agree against
the deployed contract.

`@noble/hashes` is now a direct dependency, pinned to 2.4.0 to match
`kxco-post-quantum` so a single copy resolves.

## 2.0.0

**Breaking.** Three changes, each of which will stop an existing integration
until it is configured.

**Writes to a hosted relay now require a licence key.** Signing an intent
proves who you are; it does not entitle you to have KXCO pay gas and submit the
transaction on your behalf. Pass `licenceKey`, or set `KXCO_LICENCE_KEY`
(`KXCO_LICENSE_KEY` is accepted too). It is sent as `Authorization: Bearer`,
or as `X-KXCO-Licence` where a proxy in front of the relay consumes
Authorization for its own auth.

The check happens at CONSTRUCTION, not at the first write. A service that boots
without a licence and only discovers it when the first credential is issued has
already told a user their onboarding succeeded.

A relay on `localhost`, `127.0.0.1` or `::1` needs no licence, so local
development, mocks and CI are unaffected. `requireLicence` overrides the
heuristic in both directions.

**Every response must name Armature L1.** `RelayResult` now carries
`chainId: 1111111`. A response naming another chain throws `WRONG_CHAIN`; a
response with no chain id throws `MISSING_CHAIN_ID`. A caller is about to store
that transaction hash as proof that something is on Armature L1, and handing
back a hash from somewhere else would be worse than failing. Set
`strictChainId: false` to talk to a relay that predates the field — that
relaxes the missing case only, never the wrong one.

**`relay` is now optional** and defaults to `https://relay.kxco.ai`. Omitting
it no longer throws `BAD_CONFIG`; it throws `LICENCE_REQUIRED` instead, unless
a licence is configured.

`RelayResult` also carries **`chainIdConfirmed`**. Without it, passing
`strictChainId: false` returned `chainId: 1111111` on a response that never
mentioned a chain — inventing the one fact the caller is about to store as
proof. The escape hatch may skip the check; it may not fabricate the answer.

`txHash` and `blockNumber` are now validated on arrival (`0x` + 64 hex, and a
non-negative integer). A malformed hash left unchecked travels into an
attestation envelope and resurfaces much later as "this envelope is not
anchored", pointing the blame at the wrong component. It now throws
`BAD_RELAY_RESPONSE` where the relay can be named.

### Added

`revokeKid({ kid, reason })` revokes a key outright, which is what a registry
lookup reads when it answers `revoked`. `revokeCredential` revokes an issued
credential and is unchanged.

`anchorHash({ hash, purpose })` anchors any hex SHA-256 digest. The general
form of `anchorAuditRoot` and `anchorAttestation`, which keep their own
on-chain semantics.

Both are new wire operations. A relay that has not implemented them answers
`400 UNKNOWN_OPERATION`, which the client surfaces cleanly. Verify against your
deployment before shipping code that calls them.

`registerIdentity()` and `registerAgent()` are names over the existing
`registerInstitution` and `issueAgentCredential` wire operations, so the rest
of the stack can use one vocabulary. No new server work.

`onUsageEvent` receives a structured record per relay write, for your own
observability. Off by default: a library should not write to a caller's logs
uninvited, and billing is metered relay-side regardless. The record carries the
operation, the kid and an 8-character licence prefix — never the whole licence,
because logs get shipped to places the key was never meant to reach.

`CHAIN_ID` and `DEFAULT_RELAY_URL` are exported. `chain.relay` and
`chain.licensed` are readable; the licence key itself is not.

`401` and `403` from the relay now raise `LICENCE_REJECTED` rather than a bare
`relay error 401`.

### Documentation

New `RELAY.md` states the server contract: the endpoint, the signing message,
every condition a relay must reject and with which status, the response shape,
and the operation table. `test/licence.test.js` is its executable form.

`README.md` corrects a claim that `@noble/post-quantum` is audited. It is not.
No Cure53 engagement has ever covered `@noble/post-quantum`; it is
self-audited by its maintainer only. (The other Noble packages were audited
separately: hashes by Cure53 in Jan 2022, curves and ciphers by Cure53 in
Sep 2024.)

## 1.1.6

Earlier releases. See git history.
