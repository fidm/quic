'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

import { inspect } from 'util'
import { randomBytes } from 'crypto'
import { AddressInfo } from 'dgram'
import { QuicError } from './error'

import { kVal } from './symbol'
import { Visitor, BufferVisitor, readUnsafeUIntLE, writeUnsafeUIntLE  } from './common'

const QUIC_VERSIONS = ['Q039']

export enum SessionType {
  SERVER = 0,
  CLIENT = 1,
}

export enum FamilyType {
  IPv4 = 'IPv4',
  IPv6 = 'IPv6',
}

/**
 * Returns supported version.
 */
export function getVersion (): string {
  return QUIC_VERSIONS[0]
}

/**
 * Returns supported versions array.
 */
export function getVersions (): string[] {
  return QUIC_VERSIONS.slice()
}

/**
 * Chooses the best version in the overlap of ours and theirs.
 */
export function chooseVersion (theirs: string[]): string {
  for (const v of theirs) {
    if (isSupportedVersion(v)) {
      return v
    }
  }
  return ''
}

/**
 * Returns true if the server supports this version.
 */
export function isSupportedVersion (version: string): boolean {
  return QUIC_VERSIONS.includes(version)
}

/** Protocol representing a base protocol. */
export abstract class Protocol {
  static fromBuffer (_bufv: BufferVisitor, _len?: number): Protocol {
    throw new Error(`class method "fromBuffer" is not implemented`)
  }

  protected readonly [kVal]: any
  constructor (val: any) {
    this[kVal] = val
  }

  abstract equals (other: Protocol): boolean
  abstract byteLen (arg?: any): number
  abstract writeTo (bufv: BufferVisitor, arg?: any): BufferVisitor
  abstract valueOf (): any
  abstract toString (): string

  [inspect.custom] (_depth: any, _options: any): string {
    return `<${this.constructor.name} ${this.toString()}>`
  }
}

const ConnectionIDReg = /^[0-9a-f]{16}$/
/** ConnectionID representing a connectionID. */
export class ConnectionID extends Protocol {
  static fromBuffer (bufv: BufferVisitor): ConnectionID {
    bufv.walk(8)
    if (bufv.isOutside()) {
      throw new QuicError('QUIC_INTERNAL_ERROR')
    }
    return new ConnectionID(bufv.buf.toString('hex', bufv.start, bufv.end))
  }

  static random (): ConnectionID {
    return new ConnectionID(randomBytes(8).toString('hex'))
  }

  constructor (id: string) {
    if (!ConnectionIDReg.test(id)) {
      throw new Error('invalid Connection ID')
    }
    super(id)
  }

  /**
   * @return {string} - 16 length hex string
   */
  valueOf (): string {
    return this[kVal]
  }

  equals (other: ConnectionID): boolean {
    return (other instanceof ConnectionID) && this.valueOf() === other.valueOf()
  }

  byteLen (): number {
    return 8
  }

  writeTo (bufv: BufferVisitor): BufferVisitor {
    bufv.walk(8)
    bufv.buf.write(this[kVal], bufv.start, 8, 'hex')
    return bufv
  }

  toString (): string {
    return this[kVal]
  }
}

/** PacketNumber representing a packetNumber. */
export class PacketNumber extends Protocol {
  // The lower 8, 16, 32, or 48 bits of the packet number, based on which
  // FLAG_?BYTE_SEQUENCE_NUMBER flag is set in the public flags.
  // Each Regular Packet (as opposed to the Special public reset and version
  // negotiation packets) is assigned a packet number by the sender.
  // The first packet sent by an endpoint shall have a packet number of 1, and
  // each subsequent packet shall have a packet number one larger than that of the previous packet.
  static flagToByteLen (flagBits: number): number {
    if ((flagBits & 0b11) !== flagBits) {
      throw new Error('invalid flagBits')
    }
    return flagBits > 0 ? (flagBits * 2) : 1
  }

  static fromBuffer (bufv: BufferVisitor, len: number): PacketNumber {
    bufv.walk(len)
    if (bufv.isOutside()) {
      throw new QuicError('QUIC_INTERNAL_ERROR')
    }
    return new PacketNumber(bufv.buf.readUIntLE(bufv.start, len))
  }

  constructor (val: number) {
    if (!Number.isInteger(val) || val < 1 || val > 0xffffffffffff) {
      throw new Error(`invalid PacketNumber val ${val}`)
    }

    super(val)
  }

  valueOf (): number {
    return this[kVal]
  }

  nextNumber (): PacketNumber {
    return new PacketNumber(this[kVal] + 1)
  }

  prevNumber (): PacketNumber {
    return new PacketNumber(this[kVal] - 1)
  }

  isLimitReached (): boolean {
    // If a QUIC endpoint transmits a packet with a packet number of (2^64-1),
    // that packet must include a CONNECTION_CLOSE frame with an error code of QUIC_SEQUENCE_NUMBER_LIMIT_REACHED,
    // and the endpoint must not transmit any additional packets.
    return this[kVal] >= 0xffffffffffff // but here 2^48
  }

  delta (other: PacketNumber): number {
    return Math.abs(this.valueOf() - other.valueOf())
  }

  closestTo (a: PacketNumber, b: PacketNumber): PacketNumber {
    return this.delta(a) < this.delta(b) ? a : b
  }

  flagBits (): number {
    const byteLen = this.byteLen()
    if (byteLen === 1) {
      return 0
    }
    return byteLen / 2
  }

  equals (other: PacketNumber): boolean {
    return (other instanceof PacketNumber) && this.valueOf() === other.valueOf()
  }

  byteLen (isFull: boolean = false): number {
    if (!isFull) {
      const value = this[kVal]
      if (value <= 0xff) {
        return 1
      } else if (value <= 0xffff) {
        return 2
      } else if (value <= 0xffffffff) {
        return 4
      }
    }
    return 6
  }

  writeTo (bufv: BufferVisitor, isFull: boolean = false): BufferVisitor {
    const len = isFull ? 6 : this.byteLen()
    bufv.walk(len)
    bufv.buf.writeUIntLE(this[kVal], bufv.start, len)
    return bufv
  }

  toString (): string {
    return String(this[kVal])
  }
}

/** StreamID representing a streamID. */
export class StreamID extends Protocol {
  // the Stream-ID must be even if the server initiates the stream, and odd if the client initiates the stream.
  // 0 is not a valid Stream-ID. Stream 1 is reserved for the crypto handshake,
  // which should be the first client-initiated stream.

  /**
   * 2 bits -> 8/8, 16/8, 24/8, 32/8
   */
  static flagToByteLen (flagBits: number): number {
    if ((flagBits & 0b11) !== flagBits) {
      throw new Error('invalid flagBits')
    }
    return flagBits + 1
  }

  static fromBuffer (bufv: BufferVisitor, len: number): StreamID {
    bufv.walk(len)
    if (bufv.isOutside()) {
      throw new QuicError('QUIC_INVALID_STREAM_DATA')
    }
    return new StreamID(bufv.buf.readUIntLE(bufv.start, len))
  }

  constructor (id: number) {
    // StreamID(0) is used by WINDOW_UPDATE
    if (!Number.isInteger(id) || id < 0 || id > 0xffffffff) {
      throw new Error(`invalid Stream ID ${id}`)
    }
    super(id)
  }

  valueOf (): number {
    return this[kVal]
  }

  flagBits (): number {
    return this.byteLen() - 1
  }

  nextID (): StreamID {
    const value = this[kVal] + 2
    return new StreamID(value <= 0xffffffff ? value : (value - 0xffffffff))
  }

  prevID (): StreamID {
    return new StreamID(this[kVal] - 2)
  }

  equals (other: StreamID): boolean {
    return (other instanceof StreamID) && this.valueOf() === other.valueOf()
  }

  byteLen (isFull: boolean = false): number {
    if (!isFull) {
      const value = this[kVal]
      if (value <= 0xff) {
        return 1
      } else if (value <= 0xffff) {
        return 2
      } else if (value <= 0xffffff) {
        return 3
      }
    }
    return 4
  }

  writeTo (bufv: BufferVisitor, isFull: boolean = false): BufferVisitor {
    const len = isFull ? 4 : this.byteLen()
    bufv.walk(len)
    bufv.buf.writeUIntLE(this[kVal], bufv.start, len)
    return bufv
  }

  toString (): string {
    return String(this[kVal])
  }
}

/** Offset representing a data offset. */
export class Offset extends Protocol {
  /**
   * 3 bits -> 0, 16/8, 24/8, 32/8, 40/8, 48/8, 56/8, 64/8
   */
  static flagToByteLen (flagBits: number): number {
    if ((flagBits & 0b111) !== flagBits) {
      throw new Error('invalid flagBits')
    }
    return flagBits > 0 ? (flagBits + 1) : 0
  }

  static fromBuffer (bufv: BufferVisitor, len: number): Offset {
    bufv.walk(len)
    if (bufv.isOutside()) {
      throw new QuicError('QUIC_INTERNAL_ERROR')
    }
    return new Offset(readUnsafeUIntLE(bufv.buf, bufv.start, len))
  }

  constructor (offset: number) {
    if (!Number.isSafeInteger(offset) || offset < 0) {
      throw new Error(`invalid Offset ${offset}`)
    }
    super(offset)
  }

  valueOf (): number {
    return this[kVal]
  }

  equals (other: Offset): boolean {
    return this.valueOf() === other.valueOf()
  }

  gt (other: Offset): boolean {
    return this.valueOf() > other.valueOf()
  }

  byteLen (isFull: boolean = false): number {
    if (!isFull) {
      const value = this[kVal]
      if (value === 0) {
        return 0
      } else if (value <= 0xffff) {
        return 2
      } else if (value <= 0xffffff) {
        return 3
      } else if (value <= 0xffffffff) {
        return 4
      } else if (value <= 0xffffffffff) {
        return 5
      } else if (value <= 0xffffffffffff) {
        return 6
      }
      return 7 // value should small than 0xffffffffffffff
    }
    return 8
  }

  /**
   * 0, 16/8, 24/8, 32/8, 40/8, 48/8, 56/8, 64/8 -> 3 bits
   */
  flagBits (): number {
    const byteLen = this.byteLen()
    if (byteLen === 0) {
      return 0
    }
    return byteLen > 1 ? (byteLen - 1) : 1
  }

  writeTo (bufv: BufferVisitor, isFull: boolean = false): BufferVisitor {
    const len = isFull ? 8 : this.byteLen()
    bufv.walk(len)
    if (bufv.isOutside()) {
      throw new QuicError('QUIC_INTERNAL_ERROR')
    }
    writeUnsafeUIntLE(bufv.buf, this[kVal], bufv.start, len)
    return bufv
  }

  toString (): string {
    return String(this[kVal])
  }
}

/** SocketAddress representing a socket address. */
export class SocketAddress extends Protocol {
  static fromBuffer (bufv: BufferVisitor): SocketAddress {
    const obj: AddressInfo = {
      address: '',
      family: FamilyType.IPv4,
      port: 0,
    }

    bufv.walk(2)
    if (bufv.isOutside()) {
      throw new QuicError('QUIC_INTERNAL_ERROR')
    }
    const family = bufv.buf.readUInt16LE(bufv.start)
    if (family === 0x02) {
      obj.family = FamilyType.IPv4
      bufv.walk(4)
      if (bufv.isOutside()) {
        throw new QuicError('QUIC_INTERNAL_ERROR')
      }
      obj.address = [
        bufv.buf.readUInt8(bufv.start),
        bufv.buf.readUInt8(bufv.start + 1),
        bufv.buf.readUInt8(bufv.start + 2),
        bufv.buf.readUInt8(bufv.start + 3),
      ].join('.')
      bufv.walk(2)
      if (bufv.isOutside()) {
        throw new QuicError('QUIC_INTERNAL_ERROR')
      }
      obj.port = bufv.buf.readUInt16LE(bufv.start)
    } else if (family === 0x0a) {
      obj.family = FamilyType.IPv6
      bufv.walk(16)
      if (bufv.isOutside()) {
        throw new QuicError('QUIC_INTERNAL_ERROR')
      }
      obj.address = [
        bufv.buf.readUInt16BE(bufv.start).toString(16),
        bufv.buf.readUInt16BE(bufv.start + 2).toString(16),
        bufv.buf.readUInt16BE(bufv.start + 4).toString(16),
        bufv.buf.readUInt16BE(bufv.start + 6).toString(16),
        bufv.buf.readUInt16BE(bufv.start + 8).toString(16),
        bufv.buf.readUInt16BE(bufv.start + 10).toString(16),
        bufv.buf.readUInt16BE(bufv.start + 12).toString(16),
        bufv.buf.readUInt16BE(bufv.start + 14).toString(16),
      ].join(':')
      bufv.walk(2)
      if (bufv.isOutside()) {
        throw new QuicError('QUIC_INTERNAL_ERROR')
      }
      obj.port = bufv.buf.readUInt16LE(bufv.start)
    } else {
      throw new Error('invalid SocketAddress buffer')
    }
    return new SocketAddress(obj)
  }

  port: number
  address: string
  family: FamilyType
  constructor (obj: AddressInfo) {
    if (!isAddress(obj)) {
      throw new Error(`invalid Socket Address ${JSON.stringify(obj)}`)
    }

    let address = obj.address
    if (address.includes('::')) {
      const unfold = '0:'
      if (address.startsWith('::')) {
        address = '0' + address
      } else if (address.endsWith('::')) {
        address += '0'
      }
      const _address = address.split(':')
      _address[_address.indexOf('')] = unfold.repeat(9 - _address.length).slice(0, -1)
      address = _address.join(':')
    }

    super(address)

    this.port = obj.port
    this.family = obj.family as FamilyType
    this.address = address
  }

  valueOf () {
    return {
      address: this.address,
      family: this.family as string,
      port: this.port,
    }
  }

  equals (other: SocketAddress): boolean {
    if (!(other instanceof SocketAddress)) {
      return false
    }
    return this.family === other.family && this.port === other.port && this.address === other.address
  }

  byteLen (): number {
    return this.family === FamilyType.IPv4 ? 8 : 20
  }

  writeTo (bufv: BufferVisitor): BufferVisitor {
    const address = this.address
    if (this.family === FamilyType.IPv4) {
      bufv.walk(2)
      bufv.buf.writeUInt16LE(0x02, bufv.start)
      for (const val of address.split('.')) {
        bufv.walk(1)
        bufv.buf.writeUInt8(parseInt(val, 10), bufv.start)
      }
      bufv.walk(2)
      bufv.buf.writeUInt16LE(this.port, bufv.start)
    } else {
      bufv.walk(2)
      bufv.buf.writeUInt16LE(0x0a, bufv.start)
      for (const val of address.split(':')) {
        bufv.walk(2)
        bufv.buf.writeUInt16BE(parseInt(val, 16), bufv.start)
      }
      bufv.walk(2)
      bufv.buf.writeUInt16LE(this.port, bufv.start)
    }
    return bufv
  }

  toString (): string {
    return JSON.stringify(this.valueOf())
  }
}

/** QuicTag representing a QUIC tag. */
export class QuicTag extends Protocol {
  static fromBuffer (bufv: BufferVisitor): QuicTag {
    bufv.walk(4)
    const name = bufv.buf.toString('utf8', bufv.start, bufv.end)
    const quicTag = new QuicTag(name)
    bufv.walk(4)
    if (bufv.isOutside()) {
      throw new QuicError('QUIC_INTERNAL_ERROR')
    }
    let count = bufv.buf.readInt32LE(bufv.start)

    const baseOffset = bufv.end + 8 * count
    const v2 = new Visitor(baseOffset)
    while (count-- > 0) {
      bufv.walk(4)
      if (bufv.isOutside()) {
        throw new QuicError('QUIC_INTERNAL_ERROR')
      }
      const key = bufv.buf.toString('utf8', bufv.start, bufv.end)
      bufv.walk(4)
      v2.walk(0)
      if (bufv.isOutside()) {
        throw new QuicError('QUIC_INTERNAL_ERROR')
      }
      v2.end = baseOffset + bufv.buf.readInt32LE(bufv.start)
      if (bufv.length < v2.end) {
        throw new QuicError('QUIC_INTERNAL_ERROR')
      }
      const val = bufv.buf.slice(v2.start, v2.end)
      quicTag.setTag(key, val)
    }
    bufv.reset(v2.end, v2.end)
    return quicTag
  }

  name: string
  keys: string[]
  tags: Map<string, Buffer>
  constructor (name: string) {
    super(name)
    this.name = name
    this.keys = []
    this.tags = new Map()
  }

  valueOf () {
    return {
      keys: this.keys,
      name: this.name,
      tags: this.tags,
    }
  }

  setTag (key: string, val: Buffer): void {
    if (!this.keys.includes(key)) {
      this.keys.push(key)
    }
    this.tags.set(key, val)
  }

  getTag (key: string): Buffer | undefined {
    return this.tags.get(key)
  }

  [Symbol.iterator] () {
    return this.tags[Symbol.iterator]()
  }

  equals (other: QuicTag): boolean {
    if (!(other instanceof QuicTag)) {
      return false
    }
    if (this.name !== other.name || this.keys.length !== other.keys.length) {
      return false
    }
    for (const key of this.keys) {
      const a = this.tags.get(key)
      const b = other.tags.get(key)
      if (a == null || b == null || !a.equals(b)) {
        return false
      }
    }
    return true
  }

  byteLen (): number {
    let byteLen = 8
    for (const buf of this.tags.values()) {
      byteLen += 8 + buf.length
    }
    return byteLen
  }

  writeTo (bufv: BufferVisitor): BufferVisitor {
    bufv.walk(4)
    bufv.buf.write(this.name, bufv.start, 4)
    bufv.walk(4)
    const size = this.tags.size
    bufv.buf.writeUInt32LE(size, bufv.start)

    let baseOffset = 0
    const v = new Visitor(bufv.end + 8 * size)
    for (const key of this.keys) {
      const val = this.tags.get(key)
      if (val == null) {
        throw new QuicError('QUIC_INTERNAL_ERROR')
      }
      bufv.walk(4)
      bufv.buf.write(key, bufv.start, 4)
      bufv.walk(4)
      baseOffset += val.length
      bufv.buf.writeUInt32LE(baseOffset, bufv.start)
      v.walk(val.length)
      val.copy(bufv.buf, v.start, 0, val.length)
    }
    bufv.reset(v.end, v.end)
    return bufv
  }

  toString (): string {
    return JSON.stringify(this.valueOf())
  }
}

function isAddress (address: AddressInfo): boolean {
  return address != null && address.port >= 0 && Number.isInteger(address.port) &&
    typeof address.address === 'string' &&
    (address.family === FamilyType.IPv4 || address.family === FamilyType.IPv6)
}
