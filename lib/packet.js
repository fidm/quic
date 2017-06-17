'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const { getVersions, isSupportedVersion, ConnectionID, PacketNumber, SocketAddress } = require('./protocol')
const { QuicTag } = require('./tag')
// const QuicFrame = require('./frame')
const { QuicError } = require('./error')
const { Visitor } = require('./common')

// --- QUIC Public Packet Header
//
//      0        1        2        3        4            8
// +--------+--------+--------+--------+--------+---    ---+
// | Public |    Connection ID (64)    ...                 | ->
// |Flags(8)|      (optional)                              |
// +--------+--------+--------+--------+--------+---    ---+
//
//      9       10       11        12
// +--------+--------+--------+--------+
// |      QUIC Version (32)            | ->
// |         (optional)                |
// +--------+--------+--------+--------+
//
//     13       14       15        16      17       18       19       20
// +--------+--------+--------+--------+--------+--------+--------+--------+
// |                        Diversification Nonce                          | ->
// |                              (optional)                               |
// +--------+--------+--------+--------+--------+--------+--------+--------+
//
//     21       22       23        24      25       26       27       28
// +--------+--------+--------+--------+--------+--------+--------+--------+
// |                   Diversification Nonce Continued                     | ->
// |                              (optional)                               |
// +--------+--------+--------+--------+--------+--------+--------+--------+
//
//     29       30       31        32      33       34       35       36
// +--------+--------+--------+--------+--------+--------+--------+--------+
// |                   Diversification Nonce Continued                     | ->
// |                              (optional)                               |
// +--------+--------+--------+--------+--------+--------+--------+--------+
//
//     37       38       39        40      41       42       43       44
// +--------+--------+--------+--------+--------+--------+--------+--------+
// |                   Diversification Nonce Continued                     | ->
// |                              (optional)                               |
// +--------+--------+--------+--------+--------+--------+--------+--------+
//
//     45      46       47        48       49       50
// +--------+--------+--------+--------+--------+--------+
// |           Packet Number (8, 16, 32, or 48)          |
// |                  (variable length)                  |
// +--------+--------+--------+--------+--------+--------+
// ---
//
// Public Flags:
// 0x01 = PUBLIC_FLAG_VERSION. Interpretation of this flag depends on whether the packet
//   is sent by the server or the client. When sent by the client, setting it indicates that
//   the header contains a QUIC Version (see below)...
// 0x02 = PUBLIC_FLAG_RESET. Set to indicate that the packet is a Public Reset packet.
// 0x04 = Indicates the presence of a 32 byte diversification nonce in the header.
// 0x08 = Indicates the full 8 byte Connection ID is present in the packet.
// Two bits at 0x30 indicate the number of low-order-bytes of the packet number that are present in each packet. The bits are only used for Frame Packets. For Public Reset and Version Negotiation Packets (sent by the server) which don't have a packet number, these bits are not used and must be set to 0. Within this 2 bit mask:
//   0x30 indicates that 6 bytes of the packet number is present
//   0x20 indicates that 4 bytes of the packet number is present
//   0x10 indicates that 2 bytes of the packet number is present
//   0x00 indicates that 1 byte of the packet number is present
// 0x40 is reserved for multipath use.
// 0x80 is currently unused, and must be set to 0.
exports.decodePacket = function (buf, fromServer) {
  let flag = buf.readUIntLE(0, 1, true)

  // 0x80, currently unused
  if (flag >= 127) throw new QuicError('QUIC_INTERNAL_ERROR')

  // 0x08, connectionID
  if (!(flag & 0b1000)) throw new QuicError('QUIC_INTERNAL_ERROR')
  let connectionID = new ConnectionID(buf.slice(1, 9))

  if (flag & 0b10) { // Reset Packet
    if (!fromServer) throw new QuicError('QUIC_INTERNAL_ERROR')
    return ResetPacket.fromBuffer(connectionID, buf, 9)
  }

  let hasVersion = flag & 0b1
  if (hasVersion && fromServer) { // Negotiation Packet
    return NegotiationPacket.fromBuffer(connectionID, buf, 9)
  }

  let v = new Visitor(9)
  let version
  if (hasVersion) {
    v.walk(4)
    version = buf.toString('utf8', v.start, v.end)
    if (!isSupportedVersion(version)) throw new QuicError('QUIC_INVALID_VERSION')
  }

  let nonce = (flag & 0b100) || null
  if (nonce) {
    v.walk(32)
    nonce = buf.slice(v.start, v.end)
    if (nonce.length !== 32) throw new QuicError('QUIC_INTERNAL_ERROR')
  }

  let packetNumberLen = PacketNumber.flagToByteLen((flag & 0b110000) >> 4)
  v.walk(packetNumberLen)
  let packetNumber = buf.slice(v.start, v.end)
  packetNumber = new PacketNumber(packetNumber)
  return new RegularPacket(connectionID, flag, packetNumber, version, nonce)
}

class BasePacket {
  constructor (connectionID, flag) {
    this.flag = flag
    this.connectionID = connectionID
  }

  toBuffer () {
    throw new Error('method "toBuffer" is not implemented')
  }
}

// --- Version Negotiation Packet
//      0        1        2        3        4        5        6        7       8
// +--------+--------+--------+--------+--------+--------+--------+--------+--------+
// | Public |    Connection ID (64)                                                 | ->
// |Flags(8)|                                                                       |
// +--------+--------+--------+--------+--------+--------+--------+--------+--------+
//
//      9       10       11        12       13      14       15       16       17
// +--------+--------+--------+--------+--------+--------+--------+--------+---...--+
// |      1st QUIC version supported   |     2nd QUIC version supported    |   ...
// |      by server (32)               |     by server (32)                |
// +--------+--------+--------+--------+--------+--------+--------+--------+---...--+
// ---
class NegotiationPacket extends BasePacket {
  constructor (connectionID, versions) {
    super(connectionID, 0b00001001)
    this.versions = versions
  }

  toBuffer () {
    let buf = Buffer.alloc(9 + 4 * this.versions.length)
    buf.writeUInt8(this.flag, 0, true)
    this.connectionID.toBuffer().copy(buf, 1, 0, 8)
    let offset = 9
    for (let version of this.versions) {
      buf.write(version, offset, 4)
      offset += 4
    }
    return buf
  }

  static fromConnectionID (connectionID) {
    return new NegotiationPacket(connectionID, getVersions())
  }

  static fromBuffer (connectionID, buf, offset) {
    offset = offset || 0
    let versions = []
    let v = new Visitor(offset)

    while (buf.length > v.end) {
      v.walk(4)
      let version = buf.toString('utf8', v.start, v.end)
      if (!isSupportedVersion(version)) throw new QuicError('QUIC_INVALID_VERSION')
      versions.push(version)
    }
    return new NegotiationPacket(connectionID, versions)
  }
}

// --- Public Reset Packet
//      0        1        2        3        4         8
// +--------+--------+--------+--------+--------+--   --+
// | Public |    Connection ID (64)                ...  | ->
// |Flags(8)|                                           |
// +--------+--------+--------+--------+--------+--   --+
//
//      9       10       11        12       13      14
// +--------+--------+--------+--------+--------+--------+---
// |      Quic Tag (32)                |  Tag value map      ... ->
// |         (PRST)                    |  (variable length)
// +--------+--------+--------+--------+--------+--------+---
// ---
class ResetPacket extends BasePacket {
  constructor (connectionID, nonceProof, packetNumber, socketAddress) {
    super(connectionID, 0b00001010)
    this.nonceProof = nonceProof
    this.packetNumber = packetNumber
    this.socketAddress = socketAddress
  }

  toBuffer () {
    let quicTag = new QuicTag('PRST')
    quicTag.setTag('RNON', this.nonceProof)
    quicTag.setTag('RSEQ', this.packetNumber.toFullBuffer())
    if (this.socketAddress) quicTag.setTag('CADR', this.socketAddress.toBuffer())
    let tagBuf = quicTag.toBuffer()

    let buf = Buffer.alloc(9 + tagBuf.length)
    buf.writeUInt8(this.flag, 0, true)
    this.connectionID.toBuffer().copy(buf, 1, 0, 8)
    tagBuf.copy(buf, 9, 0, tagBuf.length)
    return buf
  }

  static fromBuffer (connectionID, buf, offset) {
    let quicTag = QuicTag.fromBuffer(buf, offset)
    if (quicTag.name !== 'PRST' || quicTag.keys[0] !== 'RNON' || quicTag.keys[1] !== 'RSEQ') {
      throw new QuicError('QUIC_INVALID_PUBLIC_RST_PACKET')
    }
    let tags = quicTag.getTags()
    return new ResetPacket(connectionID, tags.RNON,
      new PacketNumber(tags.RSEQ), new SocketAddress(tags.CADR))
  }
}

// --- Frame Packet
// +--------+---...---+--------+---...---+
// | Type   | Payload | Type   | Payload |
// +--------+---...---+--------+---...---+
// ---
class RegularPacket extends BasePacket {
  constructor (connectionID, flag, packetNumber, version, nonce) {
    super(connectionID, flag)
    this.packetNumber = packetNumber
    this.version = version
    this.nonce = nonce
  }
}

exports.NegotiationPacket = NegotiationPacket
exports.ResetPacket = ResetPacket
exports.RegularPacket = RegularPacket
