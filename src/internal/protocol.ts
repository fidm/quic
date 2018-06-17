'use strict'
// **Github:** https://github.com/fidm/quic
//
// **License:** MIT

import { inspect } from 'util'
import { randomBytes } from 'crypto'
import { AddressInfo } from 'net'
import { bytesFromIP, bytesToIP } from '@fidm/x509'
import { Visitor, BufferVisitor, readUnsafeUInt, writeUnsafeUInt  } from './common'
import { QuicError } from './error'
import { kVal } from './symbol'

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
    bufv.mustWalk(8, 'QUIC_INTERNAL_ERROR')
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
    bufv.mustWalk(len, 'QUIC_INTERNAL_ERROR')
    return new PacketNumber(bufv.buf.readUIntBE(bufv.start, len))
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
    bufv.buf.writeUIntBE(this[kVal], bufv.start, len)
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
    bufv.mustWalk(len, 'QUIC_INVALID_STREAM_DATA')
    return new StreamID(bufv.buf.readUIntBE(bufv.start, len))
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
    bufv.buf.writeUIntBE(this[kVal], bufv.start, len)
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
    bufv.mustWalk(len, 'QUIC_INTERNAL_ERROR')
    return new Offset(readUnsafeUInt(bufv.buf, bufv.start, len))
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
    bufv.mustWalk(len, 'QUIC_INTERNAL_ERROR')
    writeUnsafeUInt(bufv.buf, this[kVal], bufv.start, len)
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

    bufv.mustWalk(2, 'QUIC_INTERNAL_ERROR')
    const family = bufv.buf.readUInt16BE(bufv.start)
    if (family === 0x02) {
      obj.family = FamilyType.IPv4
      bufv.mustWalk(4, 'QUIC_INTERNAL_ERROR')
      obj.address = bytesToIP(bufv.buf.slice(bufv.start, bufv.end))
      bufv.mustWalk(2, 'QUIC_INTERNAL_ERROR')
      obj.port = bufv.buf.readUInt16BE(bufv.start)
    } else if (family === 0x0a) {
      obj.family = FamilyType.IPv6
      bufv.mustWalk(16, 'QUIC_INTERNAL_ERROR')
      obj.address = bytesToIP(bufv.buf.slice(bufv.start, bufv.end))
      bufv.mustWalk(2, 'QUIC_INTERNAL_ERROR')
      obj.port = bufv.buf.readUInt16BE(bufv.start)
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
    super(obj.address)

    this.port = obj.port
    this.family = obj.family as FamilyType
    this.address = obj.address
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
    if (this.family === FamilyType.IPv4) {
      bufv.walk(2)
      bufv.buf.writeUInt16BE(0x02, bufv.start)
      const buf = bytesFromIP(this.address)
      if (buf == null || buf.length !== 4) {
        throw new Error(`Invalid IPv4 address ${this.address}`)
      }
      bufv.walk(4)
      buf.copy(bufv.buf, bufv.start, 0, 4)
      bufv.walk(2)
      bufv.buf.writeUInt16BE(this.port, bufv.start)
    } else {
      bufv.walk(2)
      bufv.buf.writeUInt16BE(0x0a, bufv.start)
      const buf = bytesFromIP(this.address)
      if (buf == null || buf.length !== 16) {
        throw new Error(`Invalid IPv6 address ${this.address}`)
      }
      bufv.walk(16)
      buf.copy(bufv.buf, bufv.start, 0, 16)
      bufv.walk(2)
      bufv.buf.writeUInt16BE(this.port, bufv.start)
    }
    return bufv
  }

  toString (): string {
    return JSON.stringify(this.valueOf())
  }
}

/** QuicTags representing a QUIC tag. */
export class QuicTags extends Protocol {
  static fromBuffer (bufv: BufferVisitor): QuicTags {
    bufv.mustWalk(4, 'QUIC_INTERNAL_ERROR')
    const tagName = bufv.buf.readUInt32BE(bufv.start)
    const quicTag = new QuicTags(tagName)
    bufv.mustWalk(4, 'QUIC_INTERNAL_ERROR')
    let count = bufv.buf.readInt16LE(bufv.start) // ignore next 2 bytes
    const baseOffset = bufv.end + 8 * count
    const v2 = new Visitor(baseOffset)
    while (count-- > 0) {
      bufv.mustWalk(4, 'QUIC_INTERNAL_ERROR')
      const key = bufv.buf.readInt32BE(bufv.start)
      bufv.mustWalk(4, 'QUIC_INTERNAL_ERROR')
      v2.walk(0)
      v2.end = baseOffset + bufv.buf.readInt32LE(bufv.start)
      if (bufv.length < v2.end) {
        throw new QuicError('QUIC_INTERNAL_ERROR')
      }
      const val = bufv.buf.slice(v2.start, v2.end)
      quicTag.set(key, val)
    }
    bufv.reset(v2.end, v2.end)
    return quicTag
  }

  name: Tag
  tags: Map<Tag, Buffer>
  constructor (name: Tag) {
    super(name)
    this.name = name
    this.tags = new Map()
  }

  valueOf () {
    const tags: any = {}
    for (const [key, value] of this.tags) {
      tags[Tag[key]] = value
    }
    return {
      name: Tag[this.name],
      tags,
    }
  }

  get size (): number {
    return this.tags.size
  }

  [Symbol.iterator] () {
    return this.tags[Symbol.iterator]()
  }

  set (key: Tag, val: Buffer): void {
    this.tags.set(key, val)
  }

  get (key: Tag): Buffer | null {
    const buf = this.tags.get(key)
    return buf == null ? null : buf
  }

  has (key: Tag): boolean {
    return this.tags.has(key)
  }

  equals (other: QuicTags): boolean {
    if (!(other instanceof QuicTags)) {
      return false
    }
    if (this.name !== other.name || this.tags.size !== other.tags.size) {
      return false
    }
    for (const key of this.tags.keys()) {
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
    bufv.buf.writeUInt32BE(this.name, bufv.start)
    bufv.walk(4)
    const size = this.tags.size
    bufv.buf.writeUInt16LE(size, bufv.start)
    bufv.buf.writeUInt16LE(0, bufv.start + 2)

    let baseOffset = 0
    const v = new Visitor(bufv.end + 8 * size)
    const keys = Array.from(this.tags.keys())
    keys.sort((a, b) => a - b)
    for (const key of keys) {
      const val = this.tags.get(key)
      if (val == null) {
        throw new QuicError('QUIC_INTERNAL_ERROR')
      }
      bufv.walk(4)
      bufv.buf.writeUInt32BE(key, bufv.start)
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

export enum Tag {
  CHLO = toTag('C', 'H', 'L', 'O'), // Client hello
  SHLO = toTag('S', 'H', 'L', 'O'), // Server hello
  SCFG = toTag('S', 'C', 'F', 'G'), // Server config
  REJ  = toTag('R', 'E', 'J', '\u{0}'),  // Reject
  SREJ = toTag('S', 'R', 'E', 'J'), // Stateless reject
  CETV = toTag('C', 'E', 'T', 'V'), // Client encrypted tag-value pairs
  PRST = toTag('P', 'R', 'S', 'T'), // Public reset
  SCUP = toTag('S', 'C', 'U', 'P'), // Server config update
  ALPN = toTag('A', 'L', 'P', 'N'), // Application-layer protocol

  // Key exchange methods
  P256 = toTag('P', '2', '5', '6'), // ECDH, Curve P-256
  C255 = toTag('C', '2', '5', '5'), // ECDH, Curve25519

  // AEAD algorithms
  AESG = toTag('A', 'E', 'S', 'G'), // AES128 + GCM-12
  CC20 = toTag('C', 'C', '2', '0'), // ChaCha20 + Poly1305 RFC7539

  // Socket receive buffer
  SRBF = toTag('S', 'R', 'B', 'F'), // Socket receive buffer

  // Congestion control feedback types
  QBIC = toTag('Q', 'B', 'I', 'C'), // TCP cubic

  // Connection options (COPT) values
  AFCW = toTag('A', 'F', 'C', 'W'), // Auto-tune flow control receive windows.
  IFW5 = toTag('I', 'F', 'W', '5'), // Set initial size of stream flow control receive window to 32KB. (2^5 KB).
  IFW6 = toTag('I', 'F', 'W', '6'), // Set initial size of stream flow control receive window to 64KB. (2^6 KB).
  IFW7 = toTag('I', 'F', 'W', '7'), // Set initial size of stream flow control receive window to 128KB. (2^7 KB).
  IFW8 = toTag('I', 'F', 'W', '8'), // Set initial size of stream flow control receive window to 256KB. (2^8 KB).
  IFW9 = toTag('I', 'F', 'W', '9'), // Set initial size of stream flow control receive window to 512KB. (2^9 KB).
  IFWA = toTag('I', 'F', 'W', 'a'), // Set initial size of stream flow control receive window to 1MB. (2^0xa KB).
  TBBR = toTag('T', 'B', 'B', 'R'), // Reduced Buffer Bloat TCP
  '1RTT' = toTag('1', 'R', 'T', 'T'), // STARTUP in BBR for 1 RTT
  '2RTT' = toTag('2', 'R', 'T', 'T'), // STARTUP in BBR for 2 RTTs
  LRTT = toTag('L', 'R', 'T', 'T'), // Exit STARTUP in BBR on loss
  BBRR = toTag('B', 'B', 'R', 'R'), // Rate-based recovery in BBR
  BBR1 = toTag('B', 'B', 'R', '1'), // Ack aggregatation v1
  BBR2 = toTag('B', 'B', 'R', '2'), // Ack aggregatation v2
  RENO = toTag('R', 'E', 'N', 'O'), // Reno Congestion Control
  TPCC = toTag('P', 'C', 'C', '\u{0}'), // Performance-Oriented Congestion Control
  BYTE = toTag('B', 'Y', 'T', 'E'), // TCP cubic or reno in bytes
  IW03 = toTag('I', 'W', '0', '3'), // Force ICWND to 3
  IW10 = toTag('I', 'W', '1', '0'), // Force ICWND to 10
  IW20 = toTag('I', 'W', '2', '0'), // Force ICWND to 20
  IW50 = toTag('I', 'W', '5', '0'), // Force ICWND to 50
  '1CON' = toTag('1', 'C', 'O', 'N'), // Emulate a single connection
  NTLP = toTag('N', 'T', 'L', 'P'), // No tail loss probe
  NCON = toTag('N', 'C', 'O', 'N'), // N Connection Congestion Ctrl
  NRTO = toTag('N', 'R', 'T', 'O'), // CWND reduction on loss
  UNDO = toTag('U', 'N', 'D', 'O'), // Undo any pending retransmits if they're likely spurious.
  TIME = toTag('T', 'I', 'M', 'E'), // Time based loss detection
  ATIM = toTag('A', 'T', 'I', 'M'), // Adaptive time loss detection
  MIN1 = toTag('M', 'I', 'N', '1'), // Min CWND of 1 packet
  MIN4 = toTag('M', 'I', 'N', '4'), // Min CWND of 4 packets, with a min rate of 1 BDP.
  TLPR = toTag('T', 'L', 'P', 'R'), // Tail loss probe delay of 0.5RTT.
  ACKD = toTag('A', 'C', 'K', 'D'), // Ack decimation style acking.
  AKD2 = toTag('A', 'K', 'D', '2'), // Ack decimation tolerating out of order packets.
  AKD3 = toTag('A', 'K', 'D', '3'), // Ack decimation style acking with 1/8 RTT acks.
  AKD4 = toTag('A', 'K', 'D', '4'), // Ack decimation with 1/8 RTT tolerating out of order.
  AKDU = toTag('A', 'K', 'D', 'U'), // Unlimited number of packets receieved before acking
  SSLR = toTag('S', 'S', 'L', 'R'), // Slow Start Large Reduction.
  NPRR = toTag('N', 'P', 'R', 'R'), // Pace at unity instead of PRR
  '5RTO' = toTag('5', 'R', 'T', 'O'), // Close connection on 5 RTOs
  '3RTO' = toTag('3', 'R', 'T', 'O'), // Close connection on 3 RTOs
  CTIM = toTag('C', 'T', 'I', 'M'), // Client timestamp in seconds since UNIX epoch.
  DHDT = toTag('D', 'H', 'D', 'T'), // Disable HPACK dynamic table.
  CONH = toTag('C', 'O', 'N', 'H'), // Conservative Handshake Retransmissions.
  LFAK = toTag('L', 'F', 'A', 'K'), // Don't invoke FACK on the first ack.
  // TODO(fayang): Remove this connection option in QUIC_VERSION_37, in which
  // MAX_HEADER_LIST_SIZE settings frame should be supported.
  SMHL = toTag('S', 'M', 'H', 'L'), // Support MAX_HEADER_LIST_SIZE settings frame.
  CCVX = toTag('C', 'C', 'V', 'X'), // Fix Cubic convex bug.
  CBQT = toTag('C', 'B', 'Q', 'T'), // Fix CubicBytes quantization.
  BLMX = toTag('B', 'L', 'M', 'X'), // Fix Cubic BetaLastMax bug.
  CPAU = toTag('C', 'P', 'A', 'U'), // Allow Cubic per-ack-updates.
  NSTP = toTag('N', 'S', 'T', 'P'), // No stop waiting frames.

  // Optional support of truncated Connection IDs.  If sent by a peer, the value
  // is the minimum number of bytes allowed for the connection ID sent to the
  // peer.
  TCID = toTag('T', 'C', 'I', 'D'), // Connection ID truncation.

  // Multipath option.
  MPTH = toTag('M', 'P', 'T', 'H'), // Enable multipath.

  NCMR = toTag('N', 'C', 'M', 'R'), // Do not attempt connection migration.

  // Enable bandwidth resumption experiment.
  BWRE = toTag('B', 'W', 'R', 'E'),  // Bandwidth resumption.
  BWMX = toTag('B', 'W', 'M', 'X'),  // Max bandwidth resumption.
  BWRS = toTag('B', 'W', 'R', 'S'),  // Server bandwidth resumption.
  BWS2 = toTag('B', 'W', 'S', '2'),  // Server bw resumption v2.

  // Enable path MTU discovery experiment.
  MTUH = toTag('M', 'T', 'U', 'H'),  // High-target MTU discovery.
  MTUL = toTag('M', 'T', 'U', 'L'),  // Low-target MTU discovery.

  // Tags for async signing experiments
  ASYN = toTag('A', 'S', 'Y', 'N'),  // Perform asynchronous signing
  SYNC = toTag('S', 'Y', 'N', 'C'),  // Perform synchronous signing

  FHL2 = toTag('F', 'H', 'L', '2'), // Force head of line blocking.

  // Proof types (i.e. certificate types)
  // NOTE: although it would be silly to do so, specifying both kX509 and kX59R
  // is allowed and is equivalent to specifying only kX509.
  X509 = toTag('X', '5', '0', '9'), // X.509 certificate, all key types
  X59R = toTag('X', '5', '9', 'R'), // X.509 certificate, RSA keys only
  CHID = toTag('C', 'H', 'I', 'D'), // Channel ID.

  // Client hello tags
  VER  = toTag('V', 'E', 'R', '\u{0}'),  // Version
  NONC = toTag('N', 'O', 'N', 'C'), // The client's nonce
  NONP = toTag('N', 'O', 'N', 'P'), // The client's proof nonce
  KEXS = toTag('K', 'E', 'X', 'S'), // Key exchange methods
  AEAD = toTag('A', 'E', 'A', 'D'), // Authenticated encryption algorithms
  COPT = toTag('C', 'O', 'P', 'T'), // Connection options
  CLOP = toTag('C', 'L', 'O', 'P'), // Client connection options
  ICSL = toTag('I', 'C', 'S', 'L'), // Idle network timeout
  SCLS = toTag('S', 'C', 'L', 'S'), // Silently close on timeout
  MSPC = toTag('M', 'S', 'P', 'C'), // Max streams per connection.
  MIDS = toTag('M', 'I', 'D', 'S'), // Max incoming dynamic streams
  IRTT = toTag('I', 'R', 'T', 'T'), // Estimated initial RTT in us.
  SWND = toTag('S', 'W', 'N', 'D'), // Server's Initial congestion window.
  SNI  = toTag('S', 'N', 'I', '\u{0}'),  // Server name indication
  PUBS = toTag('P', 'U', 'B', 'S'), // Public key values
  SCID = toTag('S', 'C', 'I', 'D'), // Server config id
  ORBT = toTag('O', 'B', 'I', 'T'), // Server orbit.
  PDMD = toTag('P', 'D', 'M', 'D'), // Proof demand.
  PROF = toTag('P', 'R', 'O', 'F'), // Proof (signature).
  CCS  = toTag('C', 'C', 'S', '\u{0}'),     // Common certificate set
  CCRT = toTag('C', 'C', 'R', 'T'), // Cached certificate
  EXPY = toTag('E', 'X', 'P', 'Y'), // Expiry
  STTL = toTag('S', 'T', 'T', 'L'), // Server Config TTL
  SFCW = toTag('S', 'F', 'C', 'W'), // Initial stream flow control receive window.
  CFCW = toTag('C', 'F', 'C', 'W'), // Initial session/connection flow control receive window.
  UAID = toTag('U', 'A', 'I', 'D'), // Client's User Agent ID.
  XLCT = toTag('X', 'L', 'C', 'T'), // Expected leaf certificate.
  TBKP = toTag('T', 'B', 'K', 'P'), // Token Binding key params.

  // Token Binding tags
  TB10 = toTag('T', 'B', '1', '0'), // TB draft 10 with P256.

  // Rejection tags
  RREJ = toTag('R', 'R', 'E', 'J'), // Reasons for server sending
  // Stateless Reject tags
  RCID = toTag('R', 'C', 'I', 'D'), // Server-designated connection ID
  // Server hello tags
  CADR = toTag('C', 'A', 'D', 'R'), // Client IP address and port
  ASAD = toTag('A', 'S', 'A', 'D'), // Alternate Server IP address and port.

  // CETV tags
  CIDK = toTag('C', 'I', 'D', 'K'), // ChannelID key
  CIDS = toTag('C', 'I', 'D', 'S'), // ChannelID signature

  // Public reset tags
  RNON = toTag('R', 'N', 'O', 'N'), // Public reset nonce proof
  RSEQ = toTag('R', 'S', 'E', 'Q'), // Rejected packet number

  // Universal tags
  PAD  = toTag('P', 'A', 'D', '\u{0}'),  // Padding

  // Server push tags
  SPSH = toTag('S', 'P', 'S', 'H'),  // Support server push.

  // clang-format on

  // These tags have a special form so that they appear either at the beginning
  // or the end of a handshake message. Since handshake messages are sorted by
  // tag value, the tags with 0 at the end will sort first and those with 255 at
  // the end will sort last.
  //
  // The certificate chain should have a tag that will cause it to be sorted at
  // the end of any handshake messages because it's likely to be large and the
  // client might be able to get everything that it needs from the small values at
  // the beginning.
  //
  // Likewise tags with random values should be towards the beginning of the
  // message because the server mightn't hold state for a rejected client hello
  // and therefore the client may have issues reassembling the rejection message
  // in the event that it sent two client hellos.
  SNO = toTag('S', 'N', 'O', '\u{0}'),  // The server's nonce
  STK = toTag('S', 'T', 'K', '\u{0}'),  // Source-address token
  CRT = toTag('C', 'R', 'T', '\u{ff}'),  // Certificate chain
  CSCT = toTag('C', 'S', 'C', 'T'),  // Signed cert timestamp (RFC6962) of leaf cert.
}

function toTag (a: string, b: string, c: string, d: string): number {
  return a.charCodeAt(0) * (0xffffff + 1) + b.charCodeAt(0) * (0xffff + 1) +
    c.charCodeAt(0) * (0xff + 1) + d.charCodeAt(0)
}

function isAddress (address: AddressInfo): boolean {
  return address != null && address.port >= 0 && Number.isInteger(address.port) &&
    typeof address.address === 'string' &&
    (address.family === FamilyType.IPv4 || address.family === FamilyType.IPv6)
}
