'use strict'
// **Github:** https://github.com/fidm/quic
//
// **License:** MIT

// https://github.com/dcodeIO/long.js/pull/60
import Long from 'long'
import { secretbox, randomBytes } from 'tweetnacl'
import { ASN1, Class, Tag, Template } from '@fidm/asn1'
import { bytesFromIP, bytesToIP } from '@fidm/x509'

// http://isthe.com/chongo/tech/comp/fnv/#FNV-param
const fnvOffset64 = Long.fromString('14695981039346656037', true, 10)
const fnvPrime64 = Long.fromString('1099511628211', true, 10)
export function fnv1a64Hash (data: Buffer): Buffer {
  let hash = Long.fromBits(fnvOffset64.getLowBits(), fnvOffset64.getHighBits(), true)
  for (const bit of data) {
    hash = hash.xor(bit)
    hash = hash.mul(fnvPrime64)
  }
  return Buffer.from(hash.toBytesBE())
}

export class SecureContext {
}

const tokenValidator: Template = {
  name: 'SourceToken',
  class: Class.UNIVERSAL,
  tag: Tag.SEQUENCE,
  value: [{
    name: 'SourceToken.IP',
    class: Class.UNIVERSAL,
    tag: Tag.OCTETSTRING,
    capture: 'ip',
  }, {
    name: 'SourceToken.timestamp',
    class: Class.UNIVERSAL,
    tag: Tag.INTEGER,
    capture: 'ts',
  }],
}

export class SourceToken {
  private key: Uint8Array
  constructor () {
    this.key = randomBytes(secretbox.keyLength)
  }

  encode (ip: string): Buffer {
    let data = bytesFromIP(ip)
    if (data == null) {
      throw new Error(`Invalid IP string: ${ip}`)
    }
    data = ASN1.Seq([
      new ASN1(Class.UNIVERSAL, Tag.OCTETSTRING, data),
      ASN1.Integer(Math.floor(Date.now() / 1000)),
    ]).toDER()

    const nonce = randomBytes(secretbox.nonceLength)
    return Buffer.concat([secretbox(data, nonce, this.key), nonce])
  }

  decode (buf: Buffer): { ip: string, ts: Date } {
    if (buf.length <= secretbox.nonceLength) {
      throw new Error('Invalid SourceToken buffer to decode')
    }
    const nonce = buf.slice(buf.length - secretbox.nonceLength)
    const data = secretbox.open(buf.slice(0, buf.length - secretbox.nonceLength), nonce, this.key)
    if (data == null) {
      throw new Error('SourceToken verify failured')
    }
    const captures = ASN1.parseDERWithTemplate(
      Buffer.from(data.buffer as ArrayBuffer, data.byteOffset, data.length), tokenValidator)
    return {
      ip: bytesToIP(captures.ip.bytes),
      ts: new Date((captures.ts.value as number) * 1000),
    }
  }
}
