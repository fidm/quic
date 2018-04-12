'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

import { inspect } from 'util'
import { randomBytes } from 'crypto'
import { AddressInfo } from 'dgram'
import { QuicError } from './error'

import { kVal } from './symbol'
import { Visitor, BufferVisitor } from './common'

const QUIC_VERSIONS = ['Q039']

export enum SessionType {
  SERVER = 0,
  CLIENT = 1,
}

export enum FamilyType {
  IPv4 = 'IPv4',
  IPv6 = 'IPv6',
}

// MaxPacketSize is the maximum packet size, including the public header, that we use for sending packets
// This is the value used by Chromium for a QUIC packet sent using IPv6 (for IPv4 it would be 1370)
// const MaxPacketSize = exports.MaxPacketSize = 1350

// MaxFrameAndPublicHeaderSize is the maximum size of a QUIC frame plus PublicHeader
// const MaxFrameAndPublicHeaderSize = exports.MaxFrameAndPublicHeaderSize = MaxPacketSize - 12 /*crypto signature*/

// DefaultMaxCongestionWindow is the default for the max congestion window
// const DefaultMaxCongestionWindow = exports.DefaultMaxCongestionWindow = 1000

// InitialCongestionWindow is the initial congestion window in QUIC packets
// const InitialCongestionWindow = exports.InitialCongestionWindow = 32

// MaxUndecryptablePackets limits the number of undecryptable packets that a
// session queues for later until it sends a public reset.
// const MaxUndecryptablePackets = exports.MaxUndecryptablePackets = 10

// PublicResetTimeout is the time to wait before sending a Public Reset when receiving
// too many undecryptable packets during the handshake
// const PublicResetTimeout = exports.PublicResetTimeout = 500 // ms

// AckSendDelay is the maximum delay that can be applied to an ACK for a retransmittable packet
// This is the value Chromium is using
// const AckSendDelay = exports.AckSendDelay = 25 // ms

// MaxStreamsPerConnection is the maximum value accepted for the number of streams per connection
// const MaxStreamsPerConnection = exports.MaxStreamsPerConnection = 100

// MaxStreamFrameSorterGaps is the maximum number of gaps between received StreamFrames
// prevents DoS attacks against the streamFrameSorter
// const MaxStreamFrameSorterGaps = exports.MaxStreamFrameSorterGaps = 1000

// CryptoMaxParams is the upper limit for the number of parameters in a crypto message.
// Value taken from Chrome.
// const CryptoMaxParams = exports.CryptoMaxParams = 128

// CryptoParameterMaxLength is the upper limit for the length of a parameter in a crypto message.
// const CryptoParameterMaxLength = exports.CryptoParameterMaxLength = 4000

// InitialIdleTimeout is the timeout before the handshake succeeds.
// const InitialIdleTimeout = exports.InitialIdleTimeout = 5 * 1000 // ms

// DefaultIdleTimeout is the default idle timeout, for the server
export const DefaultIdleTimeout = 30 * 1000

// MaxIdleTimeout is the max idle timeout
export const MaxIdleTimeout =  10 * 60 * 1000

// MaxIdleTimeoutServer is the maximum idle timeout that can be negotiated, for the server
export const MaxIdleTimeoutServer = 1 * 60 * 1000

// DefaultHandshakeTimeout is the default timeout for a connection until the crypto handshake succeeds.
// const DefaultHandshakeTimeout = exports.DefaultHandshakeTimeout = 10 * 1000

// ClosedSessionDeleteTimeout the server ignores packets arriving on a connection that is already closed
// after this time all information about the old connection will be deleted
// const ClosedSessionDeleteTimeout = exports.ClosedSessionDeleteTimeout = 60 * 1000

// NumCachedCertificates is the number of cached compressed certificate chains, each taking ~1K space
// const NumCachedCertificates = exports.NumCachedCertificates = 128

// MaxOffset is the maximum value of a ByteCount
export const MaxOffset = Number.MAX_SAFE_INTEGER

// MaxReceivePacketSize maximum packet size of any QUIC packet, based on
// ethernet's max size, minus the IP and UDP headers. IPv6 has a 40 byte header,
// UDP adds an additional 8 bytes.  This is a total overhead of 48 bytes.
// Ethernet's max packet size is 1500 bytes,  1500 - 48 = 1452.
// the current QUIC implementation uses a 1350-byte maximum QUIC packet size for IPv6,
// 1370 for IPv4. Both sizes are without IP and UDP overhead.
export const MaxReceivePacketSize = 1350

export const MaxStreamBufferSize = 1280 // todo

// DefaultTCPMSS is the default maximum packet size used in the Linux TCP implementation.
// Used in QUIC for congestion window computations in bytes.
// const DefaultTCPMSS = exports.DefaultTCPMSS = 1460

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
    bufv.v.walk(8)
    if (bufv.length < bufv.v.end) {
      throw new QuicError('QUIC_INTERNAL_ERROR')
    }
    return new ConnectionID(bufv.toString('hex', bufv.v.start, bufv.v.end))
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
    bufv.v.walk(8)
    bufv.write(this[kVal], bufv.v.start, 8, 'hex')
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
    bufv.v.walk(len)
    if (bufv.length < bufv.v.end) {
      throw new QuicError('QUIC_INTERNAL_ERROR')
    }
    return new PacketNumber(bufv.readUIntLE(bufv.v.start, len, true))
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
    bufv.v.walk(len)
    bufv.writeUIntLE(this[kVal], bufv.v.start, len, true)
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
    bufv.v.walk(len)
    if (bufv.length < bufv.v.end) {
      throw new QuicError('QUIC_INVALID_STREAM_DATA')
    }
    return new StreamID(bufv.readUIntLE(bufv.v.start, len, true))
  }

  constructor (id: number) {
    if (!Number.isInteger(id) || id < 1 || id > 0xffffffff) {
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
    bufv.v.walk(len)
    bufv.writeUIntLE(this[kVal], bufv.v.start, len, true)
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
    bufv.v.walk(len)
    if (bufv.length < bufv.v.end) {
      throw new QuicError('QUIC_INTERNAL_ERROR')
    }
    return new Offset(len > 0 ? bufv.readUIntLE(bufv.v.start, len, true) : 0)
  }

  constructor (offset: number) {
    if (!Number.isInteger(offset) || offset < 0 || offset > MaxOffset) {
      throw new Error(`invalid Offset ${offset}`)
    }
    super(offset)
  }

  valueOf (): number {
    return this[kVal]
  }

  equals (other: Offset): boolean {
    return (other instanceof Offset) && this.valueOf() === other.valueOf()
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
      return 7
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
    if (len > 0) {
      bufv.v.walk(len)
      bufv.writeUIntLE(this[kVal], bufv.v.start, len, true)
    }
    return bufv
  }

  toString (): string {
    return String(this[kVal])
  }

  nextOffset (byteLen: number): Offset {
    const value = this[kVal] + byteLen
    return new Offset(value)
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

    bufv.v.walk(2)
    if (bufv.length < bufv.v.end) {
      throw new QuicError('QUIC_INTERNAL_ERROR')
    }
    const family = bufv.readUInt16LE(bufv.v.start, true)
    if (family === 0x02) {
      obj.family = FamilyType.IPv4
      bufv.v.walk(4)
      if (bufv.length < bufv.v.end) {
        throw new QuicError('QUIC_INTERNAL_ERROR')
      }
      obj.address = [
        bufv.readUInt8(bufv.v.start, true),
        bufv.readUInt8(bufv.v.start + 1, true),
        bufv.readUInt8(bufv.v.start + 2, true),
        bufv.readUInt8(bufv.v.start + 3, true),
      ].join('.')
      bufv.v.walk(2)
      if (bufv.length < bufv.v.end) {
        throw new QuicError('QUIC_INTERNAL_ERROR')
      }
      obj.port = bufv.readUInt16LE(bufv.v.start, true)
    } else if (family === 0x0a) {
      obj.family = FamilyType.IPv6
      bufv.v.walk(16)
      if (bufv.length < bufv.v.end) {
        throw new QuicError('QUIC_INTERNAL_ERROR')
      }
      obj.address = [
        bufv.readUInt16BE(bufv.v.start, true).toString(16),
        bufv.readUInt16BE(bufv.v.start + 2, true).toString(16),
        bufv.readUInt16BE(bufv.v.start + 4, true).toString(16),
        bufv.readUInt16BE(bufv.v.start + 6, true).toString(16),
        bufv.readUInt16BE(bufv.v.start + 8, true).toString(16),
        bufv.readUInt16BE(bufv.v.start + 10, true).toString(16),
        bufv.readUInt16BE(bufv.v.start + 12, true).toString(16),
        bufv.readUInt16BE(bufv.v.start + 14, true).toString(16),
      ].join(':')
      bufv.v.walk(2)
      if (bufv.length < bufv.v.end) {
        throw new QuicError('QUIC_INTERNAL_ERROR')
      }
      obj.port = bufv.readUInt16LE(bufv.v.start, true)
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
      family: this.family,
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
      bufv.v.walk(2)
      bufv.writeUInt16LE(0x02, bufv.v.start, true)
      for (const val of address.split('.')) {
        bufv.v.walk(1)
        bufv.writeUInt8(parseInt(val, 10), bufv.v.start, true)
      }
      bufv.v.walk(2)
      bufv.writeUInt16LE(this.port, bufv.v.start, true)
    } else {
      bufv.v.walk(2)
      bufv.writeUInt16LE(0x0a, bufv.v.start, true)
      for (const val of address.split(':')) {
        bufv.v.walk(2)
        bufv.writeUInt16BE(parseInt(val, 16), bufv.v.start, true)
      }
      bufv.v.walk(2)
      bufv.writeUInt16LE(this.port, bufv.v.start, true)
    }
    return bufv
  }

  toString (): string {
    return JSON.stringify(this.valueOf())
  }

  [inspect.custom] (_depth: any, _options: any) {
    return `<SocketAddress port: ${this.port}, address: ${this.address}, family: ${this.family}>`
  }
}

/** QuicTag representing a QUIC tag. */
export class QuicTag extends Protocol {
  static fromBuffer (bufv: BufferVisitor): QuicTag {
    bufv.v.walk(4)
    const name = bufv.toString('utf8', bufv.v.start, bufv.v.end)
    const quicTag = new QuicTag(name)
    bufv.v.walk(4)
    if (bufv.length < bufv.v.end) {
      throw new QuicError('QUIC_INTERNAL_ERROR')
    }
    let count = bufv.readInt32LE(bufv.v.start)

    const baseOffset = bufv.v.end + 8 * count
    const v2 = new Visitor(baseOffset)
    while (count-- > 0) {
      bufv.v.walk(4)
      if (bufv.length < bufv.v.end) {
        throw new QuicError('QUIC_INTERNAL_ERROR')
      }
      const key = bufv.toString('utf8', bufv.v.start, bufv.v.end)
      bufv.v.walk(4)
      v2.walk(0)
      if (bufv.length < bufv.v.end) {
        throw new QuicError('QUIC_INTERNAL_ERROR')
      }
      v2.end = baseOffset + bufv.readInt32LE(bufv.v.start)
      if (bufv.length < v2.end) {
        throw new QuicError('QUIC_INTERNAL_ERROR')
      }
      const val = bufv.slice(v2.start, v2.end)
      quicTag.setTag(key, val)
    }
    bufv.v.reset(v2.end, v2.end)
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
    bufv.v.walk(4)
    bufv.write(this.name, bufv.v.start, 4)
    bufv.v.walk(4)
    const size = this.tags.size
    bufv.writeUInt32LE(size, bufv.v.start, true)

    let baseOffset = 0
    const v = new Visitor(bufv.v.end + 8 * size)
    for (const key of this.keys) {
      const val = this.tags.get(key)
      if (val == null) {
        throw new QuicError('QUIC_INTERNAL_ERROR')
      }
      bufv.v.walk(4)
      bufv.write(key, bufv.v.start, 4)
      bufv.v.walk(4)
      baseOffset += val.length
      bufv.writeUInt32LE(baseOffset, bufv.v.start, true)
      v.walk(val.length)
      val.copy(bufv, v.start, 0, val.length)
    }
    bufv.v.reset(v.end, v.end)
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
