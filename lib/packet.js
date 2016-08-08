'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const assert = require('assert')
const crypto = require('crypto')
const QuicTag = require('./frame').QuicTag
const allocBuffer = require('./util').allocBuffer

const QUIC_VERSIONS = ['Q034']

class Packet {
  constructor (connectionId, flag) {
    this.connectionId = connectionId
    this.flag = flag
  }

  toBuffer () {
    throw new Error('method "toBufferArray" is not implemented')
  }
}

class NegotiationPacket extends Packet {
  constructor (connectionId, versions) {
    super(connectionId, 0b00001001)

    this.versions = versions // ['Q034']
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
}

class ResetPacket extends Packet {
  constructor (connectionId, nonceProof, packetNumber, clientAdress) {
    super(connectionId, 0b00001010)

    this.nonceProof = nonceProof
    this.packetNumber = packetNumber
    this.clientAdress = clientAdress
  }

  toBuffer () {
    let quicTag = new QuicTag('PRST')
    quicTag.setTag('RNON', this.nonceProof)
    quicTag.setTag('RSEQ', this.packetNumber.toBuffer64())
    if (this.clientAdress) quicTag.setTag('CADR', this.clientAdress)
    let tagBuf = quicTag.toBuffer()

    let buf = allocBuffer(9 + tagBuf.length)
    buf.writeUInt8(this.flag, 0, true)
    this.connectionId.toBuffer().copy(buf, 1, 0, 8)
    tagBuf.copy(buf, 9, 0, tagBuf.length)
    return buf
  }
}

class RegularPacket extends Packet {
  constructor (connectionId, flag, packetNumber, version, nonce, byteLen) {
    super(connectionId, flag)

    this.packetNumber = packetNumber
    this.version = version
    this.nonce = nonce
    this.byteLen = byteLen
  }
}

class ConnectionId {
  constructor (buf) {
    if (buf.length !== 8) throw new Error('invalid connection id buffer')
    this.buf = buf
    this.id = [buf.readUIntLE(0, 4, true), buf.readUIntLE(4, 4, true)]
  }

  toBuffer () {
    return this.buf
  }

  equals (other) {
    if (other instanceof ConnectionId) {
      return this.id[0] === other.id[0] && this.id[1] === other.id[1]
    }
    return false
  }

  static random () {
    return new ConnectionId(crypto.randomBytes(8))
  }
}

class PacketNumber {
  constructor (buf, id) {
    this.buf = buf
    this.id = id
  }

  nextNumber () {
    let id = this.id + 1
    return PacketNumber.fromId(id <= 0xffffffffff ? id : 1)
  }

  toBuffer () {
    return this.buf
  }

  toBuffer64 () {
    let buf = new Buffer(8).fill(0)
    this.buf.copy(buf, 0, 0, this.buf.length)
    return buf
  }

  equals (other) {
    return other instanceof PacketNumber && this.id === other.id
  }

  static fromBuffer (buf) {
    let id = buf.readUIntLE(0, buf.length, true)
    let len = 0
    if (id <= 0xff) len = 1
    else if (id <= 0xffff) len = 2
    else if (id <= 0xffffffff) len = 4
    else if (id <= 0xffffffffff) len = 6
    else throw new Error('invalid packet number buffer')
    return new PacketNumber(buf.slice(0, len), id)
  }

  static fromId (id) {
    let len = 0
    // should not use bitwise shift operators, operand should be less than 32
    if (id <= 0xff) len = 1
    else if (id <= 0xffff) len = 2
    else if (id <= 0xffffffff) len = 4
    else if (id <= 0xffffffffff) len = 6
    else throw new Error('invalid packet number')
    let buf = allocBuffer(len)
    buf.writeUIntLE(id, 0, len, true)
    return new PacketNumber(buf, id)
  }
}

function parse (buf, fromServer) {
  let flag = buf.readUIntLE(0, 1, true)
  // 0x80 is currently unused, and must be set to 0
  assert(flag < 127, 'unknown public header flag')
  let connectionId = flag & 0b1000
  assert(connectionId, 'unknown public header flag')
  connectionId = new ConnectionId(buf.slice(1, 9))

  if (flag & 0b10) { // Reset Packet
    assert(fromServer, 'unknown reset public header')
    let resetTags = QuicTag.fromBuffer(buf.slice(9))
    assert(resetTags.name === 'PRST', 'unknown reset public header')
    assert(resetTags.keys[0] === 'RNON', 'unknown reset public header')
    assert(resetTags.keys[1] === 'RSEQ', 'unknown reset public header')
    let tags = resetTags.getTags()
    let packetNumber = PacketNumber.fromBuffer(tags.RSEQ)
    return new ResetPacket(connectionId, tags.RNON, packetNumber, tags.CADR)
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
  assert(packetNumber.length === packetNumberLen, 'unknown packet number')
  packetNumber = PacketNumber.fromBuffer(packetNumber)
  return new RegularPacket(connectionId, flag, packetNumber, version, nonce, end)
}

exports.parse = parse
exports.Packet = Packet
exports.NegotiationPacket = NegotiationPacket
exports.ResetPacket = ResetPacket
exports.RegularPacket = RegularPacket
exports.ConnectionId = ConnectionId
exports.PacketNumber = PacketNumber

Object.defineProperty(exports, 'QUIC_VERSIONS', {
  enumerable: true,
  get: function () { return QUIC_VERSIONS.slice() }
})
