'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const QuicID = require('./id')
const QuicTag = require('./tag')
// const QuicFrame = require('./frame')
const { QuicError } = require('./error')
const { Visitor } = require('./util')

const QUIC_VERSIONS = ['Q036']

class QuicPacket {
  constructor (connectionID, flag) {
    this.connectionID = connectionID
    this.flag = flag
  }

  toBuffer () {
    throw new Error('method "toBuffer" is not implemented')
  }

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
  static fromBuffer (buf, fromServer) {
    let flag = buf.readUIntLE(0, 1, true)
    // 0x80 is currently unused, and must be set to 0
    if (flag >= 127) throw new QuicError('QUIC_INTERNAL_ERROR')
    let connectionID = flag & 0b1000
    if (!connectionID) throw new QuicError('QUIC_INTERNAL_ERROR')
    connectionID = new QuicID.ConnectionID(buf.slice(1, 9))

    if (flag & 0b10) { // Reset Packet
      if (!fromServer) throw new QuicError('QUIC_INTERNAL_ERROR')
      return ResetPacket.fromBuffer(connectionID, buf, 9)
    }

    let version = (flag & 0b1) || null
    if (version && fromServer) { // Negotiation Packet
      return NegotiationPacket.fromBuffer(connectionID, buf, 9)
    }

    let v = new Visitor(9)
    if (version) {
      v.walk(4)
      version = buf.toString('utf8', v.start, v.end)
      if (!QuicPacket.isValidVersion(version)) throw new QuicError('QUIC_INVALID_VERSION')
    }

    let nonce = (flag & 0b100) || null
    if (nonce) {
      v.walk(32)
      nonce = buf.slice(v.start, v.end)
      if (nonce.length !== 32) throw new QuicError('QUIC_INTERNAL_ERROR')
    }

    let packetNumberLen = QuicID.PacketNumber.flagToByteLen((flag & 0b110000) >> 4)
    v.walk(packetNumberLen)
    let packetNumber = buf.slice(v.start, v.end)
    packetNumber = new QuicID.PacketNumber(packetNumber)
    return new RegularPacket(connectionID, flag, packetNumber, version, nonce)
  }
}

class NegotiationPacket extends QuicPacket {
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
    return new NegotiationPacket(connectionID, QUIC_VERSIONS.slice())
  }

  static fromBuffer (connectionID, buf, offset) {
    offset = offset || 0
    let versions = []
    let v = new Visitor(offset)

    while (buf.length > v.end) {
      v.walk(4)
      let version = buf.toString('utf8', v.start, v.end)
      if (!QuicPacket.isValidVersion(version)) throw new QuicError('QUIC_INVALID_VERSION')
      versions.push(version)
    }
    return new NegotiationPacket(connectionID, versions)
  }
}

class ResetPacket extends QuicPacket {
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
      new QuicID.PacketNumber(tags.RSEQ), new QuicID.SocketAddress(tags.CADR))
  }
}

class RegularPacket extends QuicPacket {
  constructor (connectionID, flag, packetNumber, version, nonce) {
    super(connectionID, flag)
    this.packetNumber = packetNumber
    this.version = version
    this.nonce = nonce
  }
}

QuicPacket.NegotiationPacket = NegotiationPacket
QuicPacket.ResetPacket = ResetPacket
QuicPacket.RegularPacket = RegularPacket
QuicPacket.isValidVersion = function (version) {
  return QUIC_VERSIONS.indexOf(version) >= 0
}

Object.defineProperty(QuicPacket, 'QUIC_VERSIONS', {
  enumerable: true,
  get: function () { return QUIC_VERSIONS.slice() }
})

module.exports = QuicPacket
