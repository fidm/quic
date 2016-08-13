'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const assert = require('assert')
const QuicID = require('./id')
const QuicTag = require('./tag')
// const QuicFrame = require('./frame')
const allocBuffer = require('./util').allocBuffer

const QUIC_VERSIONS = ['Q034']

class QuicPacket {
  constructor (connectionId, flag) {
    this.connectionId = connectionId
    this.flag = flag
  }

  toBuffer () {
    throw new Error('method "toBuffer" is not implemented')
  }
}

class NegotiationPacket extends QuicPacket {
  constructor (connectionId, versions) {
    super(connectionId, 0b00001001)

    this.versions = versions
  }

  toBuffer () {
    let buf = allocBuffer(9 + 4 * this.versions.length)
    buf.writeUInt8(this.flag, 0, true)
    this.connectionId.toBuffer().copy(buf, 1, 0, 8)
    let offset = 9
    for (let version of this.versions) {
      buf.write(version, offset, 4)
      offset += 4
    }
    return buf
  }

  static fromConnectionID (connectionId) {
    return new NegotiationPacket(connectionId, QUIC_VERSIONS.slice())
  }
}

class ResetPacket extends QuicPacket {
  constructor (connectionId, nonceProof, packetNumber, socketAddress) {
    super(connectionId, 0b00001010)

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

    let buf = allocBuffer(9 + tagBuf.length)
    buf.writeUInt8(this.flag, 0, true)
    this.connectionId.toBuffer().copy(buf, 1, 0, 8)
    tagBuf.copy(buf, 9, 0, tagBuf.length)
    return buf
  }
}

class RegularPacket extends QuicPacket {
  constructor (connectionId, flag, packetNumber, version, nonce, byteLen) {
    super(connectionId, flag)

    this.packetNumber = packetNumber
    this.version = version
    this.nonce = nonce
    this.byteLen = byteLen
  }
}

function parse (buf, fromServer) {
  let flag = buf.readUIntLE(0, 1, true)
  // 0x80 is currently unused, and must be set to 0
  assert(flag < 127, 'unknown public header flag')
  let connectionId = flag & 0b1000
  assert(connectionId, 'unknown public header flag')
  connectionId = new QuicID.ConnectionID(buf.slice(1, 9))

  if (flag & 0b10) { // Reset Packet
    assert(fromServer, 'unknown reset public header')
    let resetTags = QuicTag.fromBuffer(buf.slice(9))
    assert(resetTags.name === 'PRST', 'unknown reset public header')
    assert(resetTags.keys[0] === 'RNON', 'unknown reset public header')
    assert(resetTags.keys[1] === 'RSEQ', 'unknown reset public header')
    let tags = resetTags.getTags()
    return new ResetPacket(connectionId, tags.RNON,
      new QuicID.PacketNumber(tags.RSEQ), new QuicID.SocketAddress(tags.CADR))
  }

  let version = (flag & 0b1) || null
  version = buf.toString('utf8', 9, 13)
  assert(QUIC_VERSIONS.indexOf(version) >= 0, 'unknown QUIC version')
  let start = 13
  let end = 13

  if (version && fromServer) { // Negotiation Packet
    let versions = [version]
    end = start + 4
    while (buf.length >= end) {
      let version = buf.toString('utf8', start, end)
      assert(QUIC_VERSIONS.indexOf(version) >= 0, 'unknown QUIC version')
      versions.push(version)
      start = end
      end += 4
    }
    return new NegotiationPacket(connectionId, versions)
  }

  let nonce = (flag & 0b100) || null
  if (nonce) {
    end = start + 32
    nonce = buf.slice(start, end)
    assert(nonce.length === 32, 'unknown QUIC version')
    start = end
  }

  let packetNumberLen = 1
  switch (flag & 0b110000) {
    case 0b110000:
      packetNumberLen = 6
      break
    case 0b100000:
      packetNumberLen = 4
      break
    case 0b010000:
      packetNumberLen = 2
      break
  }

  end = start + packetNumberLen
  let packetNumber = buf.slice(start, end)
  packetNumber = new QuicID.PacketNumber(packetNumber)
  return new RegularPacket(connectionId, flag, packetNumber, version, nonce, end)
}

exports.parse = parse
exports.QuicPacket = QuicPacket
exports.NegotiationPacket = NegotiationPacket
exports.ResetPacket = ResetPacket
exports.RegularPacket = RegularPacket
exports.isValidVersion = function (version) {
  return QUIC_VERSIONS.indexOf(version) >= 0
}

Object.defineProperty(exports, 'QUIC_VERSIONS', {
  enumerable: true,
  get: function () { return QUIC_VERSIONS.slice() }
})
