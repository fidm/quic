'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const assert = require('assert')
const crypto = require('crypto')
const allocBuffer = Buffer.allocUnsafe || ((size) => new Buffer(size))

class Packet {
  constructor (flag, connectionId) {
    this.flag = flag
    this.connectionId = connectionId
  }

  toBufferArray () {
    throw new Error('method "toBufferArray" is not implemented')
  }

  static fromBuffer (buf, fromServer) {
    let flag = buf.readUIntLE(0, 1, true)
    // 0x80 is currently unused, and must be set to 0
    assert(flag > 127, 'unknown public header')
    let connectionId = flag & 0b1000
    assert(connectionId, 'unknown public header')
    connectionId = new ConnectionId(buf.slice(1, 9))

    if (flag & 0b10) { // Reset Packet
      assert(!fromServer, 'unknown reset public header')
      assert(buf.slice(9, 13).toString() === 'PRST', 'unknown reset public header')
      assert(buf.slice(13, 17).toString() === 'RNON', 'unknown reset public header')
      let nonceProof = buf.slice(17, 25)
      assert(buf.slice(25, 29).toString() === 'RSEQ', 'unknown reset public header')
      let packetNumber = new PacketNumber(buf.slice(29, 37))
      let clientAdress = null
      if (buf.slice(37, 41).toString() === 'CADR') { // TODO
        clientAdress = buf.slice(41, 49)
      }
      return new ResetPacket(flag, connectionId, nonceProof, packetNumber, clientAdress)
    }

    let version = (flag & 0b1) || null
    version = buf.slice(9, 13).toString()
    assert(version === 'Q034', 'unknown QUIC version')
    if (version && fromServer) {
      return new NegotiationPacket(flag, connectionId, [version])
    }

    let nonce = (flag & 0b100) || null
    let start = 13
    let end = 13
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
    return new RegularPacket(flag, connectionId, packetNumber, version, nonce, end)
  }
}

class NegotiationPacket extends Packet {
  constructor (flag, connectionId, versions) {
    super(flag, connectionId)

    this.versions = versions // ['Q034']
  }

  toBufferArray () {
    let buf = allocBuffer(9 + 4 * this.versions.length)
    buf.writeUInt8(0b00001001, 0, true)
    this.connectionId.toBuffer().copy(buf, 1, 0, 8)
    let offset = 9
    for (let version of this.versions) {
      buf.write(version, offset, 4)
      offset += 4
    }
    return [buf]
  }
}

class ResetPacket extends Packet {
  constructor (flag, connectionId, nonceProof, packetNumber, clientAdress) {
    super(flag, connectionId)

    this.nonceProof = nonceProof
    this.packetNumber = packetNumber
    this.clientAdress = clientAdress
  }

  toBufferArray () {
    let buf = allocBuffer(9 + 4 + 12 + 12)
    buf.writeUInt8(0b00001010, 0, true)
    this.connectionId.toBuffer().copy(buf, 1, 0, 8)
    buf.write('PRST', 9, 4)
    buf.write('RNON', 13, 4)
    buf.write(this.nonceProof, 17, 8)
    this.packetNumber.toBuffer64().copy(buf, 25, 0, 8)
    let bufs = [buf]
    if (this.clientAdress) bufs.push(this.clientAdress.toBuffer())
    return bufs
  }
}

class RegularPacket extends Packet {
  constructor (flag, connectionId, packetNumber, version, nonce, byteLen) {
    super(flag, connectionId)

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
    return new ConnectionId(crypto.randomBytes(64))
  }
}

class PacketNumber {
  constructor (buf) {
    this.buf = buf
    this.id = buf.readUIntLE(0, buf.length, true)
  }

  toBuffer () {
    return this.buf
  }

  toBuffer64 () {
    let buf = this.buf
    if (buf.length !== 8) {
      buf = new Buffer(8)
      this.buf.copy(buf, 0, 0, this.buf.length)
    }
    return buf
  }

  equals (other) {
    return other instanceof PacketNumber && this.id === other.id
  }

  static fromBuffer (buf) {
    return new PacketNumber(buf)
  }
}

exports.Packet = Packet
exports.NegotiationPacket = NegotiationPacket
exports.ResetPacket = ResetPacket
exports.RegularPacket = RegularPacket
exports.ConnectionId = ConnectionId
exports.PacketNumber = PacketNumber
