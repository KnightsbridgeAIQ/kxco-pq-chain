# Changelog

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
