'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const crypto = require('crypto')
const allocBuffer = require('./util').allocBuffer
const ID = Symbol('QuicID.id')
const BUF = Symbol('QuicID.buf')

class QuicID {
  constructor (buf) {
    if (!Buffer.isBuffer(buf)) throw new Error('invalid QuicID buffer')
    this[BUF] = buf
  }

  equals (other) {
    return this[BUF].equals(other[BUF])
  }

  toBuffer () {
    return this[BUF]
  }

  toString () {
    return this[BUF].toString('hex')
  }
}

class ConnectionID extends QuicID {
  constructor (buf) {
    super(buf)
    if (buf.length !== 8) throw new Error('invalid ConnectionID buffer')
  }

  static fromString (str) {
    return new ConnectionID(new Buffer(str, 'hex'))
  }

  static random () {
    return new ConnectionID(crypto.randomBytes(8))
  }
}

class PacketNumber extends QuicID {
  constructor (buf) {
    super(buf)

    let id = buf.readUIntLE(0, buf.length, true)
    let len = 0
    if (id <= 0xff) len = 1
    else if (id <= 0xffff) len = 2
    else if (id <= 0xffffffff) len = 4
    else if (id <= 0xffffffffffff) len = 6
    else throw new Error('invalid PacketNumber buffer')

    if (buf.length !== len) this[BUF] = buf.slice(0, len)
    this[ID] = id
  }

  get id () {
    return this[ID]
  }

  nextNumber () {
    let id = this[ID] + 1
    return PacketNumber.fromId(id <= 0xffffffffffff ? id : 1)
  }

  toFullBuffer () {
    let buf = allocBuffer(8)
    this[BUF].copy(buf, 0, 0, this[BUF].length)
    return buf
  }

  equals (other) {
    return other instanceof PacketNumber && this[ID] === other[ID]
  }

  static fromId (id) {
    let len = 0
    // should not use bitwise shift operators, operand should be less than 32
    if (id <= 0xff) len = 1
    else if (id <= 0xffff) len = 2
    else if (id <= 0xffffffff) len = 4
    else if (id <= 0xffffffffffff) len = 6
    else throw new Error('invalid packet number')
    let buf = allocBuffer(len)
    buf.writeUIntLE(id, 0, len, true)
    return new PacketNumber(buf)
  }
}

class StreamId extends QuicID {
  constructor (buf) {
    super(buf)
    if (buf.length !== 4) throw new Error('invalid StreamId buffer')
    this[ID] = buf.readInt32LE(0, true)
  }

  get id () {
    return this[ID]
  }

  nextId () {
    let id = this[ID] + 2
    return StreamId.fromId(id <= 0xffffffff ? id : 0)
  }

  equals (other) {
    return other instanceof StreamId && this[ID] === other[ID]
  }

  static fromId (id) {
    let buf = allocBuffer(4)
    buf.writeUInt32LE(id, 0, true)
    return new StreamId(buf)
  }
}

class SocketAddress extends QuicID {
  constructor (buf) {
    super(buf)

    let family = buf.readUInt16LE(0, true)
    if (family === 0x02) {
      if (buf.length !== 8) throw new Error('invalid IPv4 SocketAddress buffer')
      this.family = 'IPv4'
      this.address = [
        buf.readUInt8(2, true),
        buf.readUInt8(3, true),
        buf.readUInt8(4, true),
        buf.readUInt8(5, true)
      ].join('.')
      this.port = buf.readUInt16LE(6, true)
    } else if (family === 0x0a) {
      if (buf.length !== 20) throw new Error('invalid IPv4 SocketAddress buffer')
      this.family = 'IPv6'
      this.address = [
        buf.readUInt16BE(2, true).toString(16),
        buf.readUInt16BE(4, true).toString(16),
        buf.readUInt16BE(6, true).toString(16),
        buf.readUInt16BE(8, true).toString(16),
        buf.readUInt16BE(10, true).toString(16),
        buf.readUInt16BE(12, true).toString(16),
        buf.readUInt16BE(14, true).toString(16),
        buf.readUInt16BE(16, true).toString(16)
      ].join(':')
      this.port = buf.readUInt16LE(18, true)
    } else throw new Error('invalid SocketAddress buffer')
  }

  static fromObject (address) {
    if (!isAddress(address)) throw new Error('invalid SocketAddress object')

    let port = address.port
    let family = address.family
    address = address.address

    let buf = null
    if (family === 'IPv4') {
      buf = allocBuffer(8)
      buf.writeUInt16LE(0x02, 0, true)
      let offset = 2
      for (let val of address.split('.')) {
        buf.writeUInt8(parseInt(val, 10), offset, true)
        offset += 1
      }
      buf.writeUInt16LE(port, offset, true)
    } else {
      if (address.includes('::')) {
        let unfold = '0:'
        if (address.startsWith('::')) address = '0' + address
        else if (address.endsWith('::')) address += '0'
        address = address.split(':')
        address[address.indexOf('')] = unfold.repeat(9 - address.length).slice(0, -1)
        address = address.join(':')
      }

      buf = allocBuffer(20)
      buf.writeUInt16LE(0x0a, 0, true)
      let offset = 2
      for (let val of address.split(':')) {
        buf.writeUInt16BE(parseInt(val, 16), offset, true)
        offset += 2
      }
      buf.writeUInt16LE(port, 18, true)
    }
    return new SocketAddress(buf)
  }
}

QuicID.ConnectionID = ConnectionID
QuicID.PacketNumber = PacketNumber
QuicID.StreamId = StreamId
QuicID.SocketAddress = SocketAddress

module.exports = QuicID

function isAddress (address) {
  return address && address.port >= 0 &&
    address.port === Math.floor(address.port) &&
    typeof address.address === 'string' &&
    (address.family === 'IPv4' || address.family === 'IPv6')
}
