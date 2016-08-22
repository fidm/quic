'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const crypto = require('crypto')
const inspect = require('util').inspect

const VAL = Symbol('QuicID.val')
const BUF = Symbol('QuicID.buf')

class QuicID {
  constructor (buf) {
    if (!Buffer.isBuffer(buf)) throw new Error('invalid QuicID buffer')
    this[BUF] = buf
  }

  equals (other) {
    return this[BUF].equals(other[BUF])
  }

  get byteLen () {
    return this[BUF].length
  }

  toJSON () {
    let keys = Object.keys(this)
    if (keys.length) {
      let object = {}
      for (let key of keys) object[key] = this[key]
      return object
    }

    if (this[VAL]) return {value: this[VAL]}
    else if (this[BUF]) return this[BUF].toJSON()
    return {}
  }

  inspect () {
    return `${this.constructor.name} ${inspect(this.toJSON())}`
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
    if (!buf.length) throw new Error('invalid PacketNumber buffer')

    let value = buf.readUIntLE(0, buf.length, true)
    let len = 0
    if (value <= 0xff) len = 1
    else if (value <= 0xffff) len = 2
    else if (value <= 0xffffffff) len = 4
    else if (value <= 0xffffffffffff) len = 6
    else throw new Error('invalid PacketNumber buffer')

    if (buf.length !== len) {
      this[BUF] = Buffer.alloc(len)
      this[BUF].writeUIntLE(value, 0, len, true)
    }
    this[VAL] = value
  }

  get value () {
    return this[VAL]
  }

  nextNumber () {
    let value = this[VAL] + 1
    return PacketNumber.fromValue(value <= 0xffffffffffff ? value : 1)
  }

  toFullBuffer () {
    let buf = Buffer.alloc(8)
    this[BUF].copy(buf, 0, 0, this[BUF].length)
    return buf
  }

  equals (other) {
    return other instanceof PacketNumber && this[VAL] === other[VAL]
  }

  delta (other) {
    return Math.abs(this[VAL] - other[VAL])
  }

  closestTo (a, b) {
    return this.delta(a) < this.delta(b) ? a : b
  }

  // 8/8, 16/8, 32/8, 48/8 -> 2 bits
  get flagBits () {
    let byteLen = this.byteLen
    if (byteLen === 1) return 0
    return byteLen / 2
  }
  // 2 bits -> 8/8, 16/8, 32/8, 48/8
  static flagToByteLen (flagBits) {
    if ((flagBits & 0b11) !== flagBits) throw new Error('invalid flagBits')
    return flagBits ? (flagBits * 2) : 1
  }

  static fromValue (value) {
    let len = 0
    // should not use bitwise shift operators, operand should be less than 32
    if (value <= 0xff) len = 1
    else if (value <= 0xffff) len = 2
    else if (value <= 0xffffffff) len = 4
    else if (value <= 0xffffffffffff) len = 6
    else throw new Error('invalid packet number')
    let buf = Buffer.alloc(len)
    buf.writeUIntLE(value, 0, len, true)
    return new PacketNumber(buf)
  }
}

class StreamID extends QuicID {
  constructor (buf) {
    super(buf)
    if (!buf.length) throw new Error('invalid StreamID buffer')

    let value = buf.readUIntLE(0, buf.length, true)
    let len = 0
    if (value <= 0xff) len = 1
    else if (value <= 0xffff) len = 2
    else if (value <= 0xffffff) len = 3
    else if (value <= 0xffffffff) len = 4
    else throw new Error('invalid StreamID buffer')

    if (buf.length !== len) {
      this[BUF] = Buffer.alloc(len)
      this[BUF].writeUIntLE(value, 0, len, true)
    }
    this[VAL] = value
  }

  get value () {
    return this[VAL]
  }

  nextID () {
    let value = this[VAL] + 2
    return StreamID.fromValue(value <= 0xffffffff ? value : (value - 0xffffffff))
  }

  toFullBuffer () {
    let buf = Buffer.alloc(4)
    this[BUF].copy(buf, 0, 0, this[BUF].length)
    return buf
  }

  equals (other) {
    return other instanceof StreamID && this[VAL] === other[VAL]
  }

  // 8/8, 16/8, 24/8, 32/8 -> 2 bits
  get flagBits () {
    return this.byteLen - 1
  }
  // 2 bits -> 8/8, 16/8, 24/8, 32/8
  static flagToByteLen (flagBits) {
    if ((flagBits & 0b11) !== flagBits) throw new Error('invalid flagBits')
    return flagBits + 1
  }

  static fromValue (value) {
    let len = 0
    if (value <= 0xff) len = 1
    else if (value <= 0xffff) len = 2
    else if (value <= 0xffffff) len = 3
    else if (value <= 0xffffffff) len = 4
    else throw new Error('invalid StreamID value')
    let buf = Buffer.alloc(len)
    buf.writeUIntLE(value, 0, len, true)
    return new StreamID(buf)
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
      buf = Buffer.alloc(8)
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

      buf = Buffer.alloc(20)
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

class Offset extends QuicID {
  constructor (buf) {
    super(buf)

    let value = buf.length ? buf.readUIntLE(0, buf.length, true) : 0
    let len = 0
    // 0, 16, 24, 32, 40, 48 bits long
    // Max offset < 256TB, can't support 56 or 64 bits offset in JavaScript
    if (value === 0) len = 0
    else if (value <= 0xffff) len = 2
    else if (value <= 0xffffff) len = 3
    else if (value <= 0xffffffff) len = 4
    else if (value <= 0xffffffffff) len = 5
    else if (value <= 0xffffffffffff) len = 6
    else throw new Error('invalid Offset buffer')

    if (buf.length !== len) {
      this[BUF] = Buffer.alloc(len)
      if (value) this[BUF].writeUIntLE(value, 0, len, true)
    }
    this[VAL] = value
  }

  get value () {
    return this[VAL]
  }

  nextOffset (byteLen) {
    let value = this[VAL] + byteLen
    return Offset.fromValue(value)
  }

  toFullBuffer () {
    let buf = Buffer.alloc(8)
    this[BUF].copy(buf, 0, 0, this[BUF].length)
    return buf
  }

  // 0, 16/8, 24/8, 32/8, 40/8, 48/8, 56/8, 64/8 -> 3 bits
  get flagBits () {
    let byteLen = this.byteLen
    if (byteLen === 0) return 0
    return (byteLen - 1) || 1
  }
  // 3 bits -> 0, 16/8, 24/8, 32/8, 40/8, 48/8, 56/8, 64/8
  static flagToByteLen (flagBits) {
    if ((flagBits & 0b111) !== flagBits) throw new Error('invalid flagBits')
    return flagBits ? (flagBits + 1) : 0
  }

  static fromValue (value) {
    let len = 0
    if (value === 0) len = 0
    else if (value <= 0xffff) len = 2
    else if (value <= 0xffffff) len = 3
    else if (value <= 0xffffffff) len = 4
    else if (value <= 0xffffffffff) len = 5
    else if (value <= 0xffffffffffff) len = 6
    else throw new Error('invalid Offset buffer')
    let buf = Buffer.alloc(len)
    if (value) buf.writeUIntLE(value, 0, len, true)
    return new Offset(buf)
  }
}

QuicID.ConnectionID = ConnectionID
QuicID.PacketNumber = PacketNumber
QuicID.StreamID = StreamID
QuicID.SocketAddress = SocketAddress
QuicID.Offset = Offset

module.exports = QuicID

function isAddress (address) {
  return address && address.port >= 0 &&
    address.port === Math.floor(address.port) &&
    typeof address.address === 'string' &&
    (address.family === 'IPv4' || address.family === 'IPv6')
}
