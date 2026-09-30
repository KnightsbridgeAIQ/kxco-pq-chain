// RFC 8785 JSON Canonicalization Scheme (JCS), subset.
// Copied from kxco-pq-cli/src/jcs.js, with one difference: an object key named
// "__proto__" is refused (see walk()). Otherwise its output must not change,
// because the relay recomputes these bytes with the same algorithm.

import { KxcoChainError } from './errors.js'

/**
 * Canonicalize a JSON-serializable value per (a subset of) RFC 8785.
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalize(value) {
  return JSON.stringify(walk(value))
}

function walk(v) {
  if (v === null) return null
  if (typeof v === 'boolean') return v
  if (typeof v === 'string')  return v
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new TypeError('JCS: non-finite numbers are not representable in JSON')
    if (!Number.isInteger(v)) throw new TypeError('JCS subset: floats are not supported')
    return v
  }
  if (Array.isArray(v)) return v.map(walk)
  if (v && typeof v === 'object') {
    const out = {}
    for (const k of Object.keys(v).sort()) {
      // Assigning "__proto__" on a plain object sets its prototype rather than
      // adding a key, so the member would be left out of the signed bytes. It
      // is refused, not serialised, so that the bytes stay the ones the relay
      // computes.
      if (k === '__proto__') {
        throw new KxcoChainError('JCS: an object key named "__proto__" is not supported', { code: 'BAD_ARGUMENT' })
      }
      const child = walk(v[k])
      if (child === undefined) continue
      out[k] = child
    }
    return out
  }
  if (v === undefined) return undefined
  throw new TypeError(`JCS: unsupported value of type ${typeof v}`)
}
