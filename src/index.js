export { KxcoChain, CHAIN_ID, DEFAULT_RELAY_URL } from './client.js'
export { KxcoChainError } from './errors.js'
export { buildIntent, buildSigningMessage, randomNonce } from './intents.js'
export { canonicalize }   from './jcs.js'

// ── Phase 3: on-chain verification ────────────────────────────────────────
//
// Version 2 intents, for the path where PQVerifyingRelay verifies the
// signature on-chain through the ML-DSA-65 precompile rather than the relay
// verifying it off-chain. v1 above is unchanged and stays supported.
export {
  authorisingMessage,
  signIntentV2,
  abiEncode,
  fetchOperationTags,
  OPERATION_TAGS_SELECTOR,
  ARGS as INTENT_V2_ARGS,
  OPERATION_TAGS,
  OPERATION_NAMES,
  // CHAIN_ID already comes from client.js; both are 1111111 and one export wins.
} from './intents-v2.js'
