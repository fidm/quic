'use strict'
// **Github:** https://github.com/fidm/quic
//
// **License:** MIT

// https://github.com/dcodeIO/long.js/pull/60
import Long from 'long'

// http://isthe.com/chongo/tech/comp/fnv/#FNV-param
const fnvOffset64 = Long.fromString('14695981039346656037', true, 10)
const fnvPrime64 = Long.fromString('1099511628211', true, 10)
export function fnv1a64Hash (data: Buffer, le: boolean): Buffer {
  let hash = Long.fromBits(fnvOffset64.getLowBits(), fnvOffset64.getHighBits(), true)
  for (const bit of data) {
    hash = hash.xor(bit)
    hash = hash.mul(fnvPrime64)
  }
  return Buffer.from(hash.toBytes(le))
}

export class SecureContext {
}

export class SourceToken {
}
