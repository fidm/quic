'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const util = require('util')
const crypto = require('crypto')
// const { QuicError } = require('./error')

const VAL = Symbol('BaseProtocol.val')
const BUF = Symbol('BaseProtocol.buf')

const QUIC_VERSIONS = ['Q039']

exports.QUIC_SERVER = 0
exports.QUIC_CLIENT = 1

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

// PublicResetTimeout is the time to wait before sending a Public Reset when receiving too many undecryptable packets during the handshake
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
// const DefaultIdleTimeout = exports.DefaultIdleTimeout = 30 * 1000

// MaxIdleTimeoutServer is the maximum idle timeout that can be negotiated, for the server
// const MaxIdleTimeoutServer = exports.MaxIdleTimeoutServer = 1 * 60 * 1000

// MaxIdleTimeoutClient is the idle timeout that the client suggests to the server
// const MaxIdleTimeoutClient = exports.MaxIdleTimeoutClient =  2 * 60 * 1000

// DefaultHandshakeTimeout is the default timeout for a connection until the crypto handshake succeeds.
// const DefaultHandshakeTimeout = exports.DefaultHandshakeTimeout = 10 * 1000

// ClosedSessionDeleteTimeout the server ignores packets arriving on a connection that is already closed
// after this time all information about the old connection will be deleted
// const ClosedSessionDeleteTimeout = exports.ClosedSessionDeleteTimeout = 60 * 1000

// NumCachedCertificates is the number of cached compressed certificate chains, each taking ~1K space
// const NumCachedCertificates = exports.NumCachedCertificates = 128

// MaxOffset is the maximum value of a ByteCount
const MaxOffset = exports.MaxOffset = Number.MAX_SAFE_INTEGER

// MaxReceivePacketSize maximum packet size of any QUIC packet, based on
// ethernet's max size, minus the IP and UDP headers. IPv6 has a 40 byte header,
// UDP adds an additional 8 bytes.  This is a total overhead of 48 bytes.
// Ethernet's max packet size is 1500 bytes,  1500 - 48 = 1452.
exports.MaxReceivePacketSize = 1452

// DefaultTCPMSS is the default maximum packet size used in the Linux TCP implementation.
// Used in QUIC for congestion window computations in bytes.
// const DefaultTCPMSS = exports.DefaultTCPMSS = 1460

/**
 * Returns supported versions array.
 *
 * @return {Array} supported versions
 * @api public
 */
exports.getVersion = function () {
  return QUIC_VERSIONS[0]
}

/**
 * Returns supported versions array.
 *
 * @return {Array} supported versions
 * @api public
 */
exports.getVersions = function () {
  return QUIC_VERSIONS.slice()
}

/**
 * Chooses the best version in the overlap of ours and theirs.
 *
 * @param {Array} versions...
 * @return {String}
 * @api public
 */
exports.chooseVersion = function (theirs) {
  for (let v of theirs) {
    if (exports.isSupportedVersion(v)) return v
  }
  return ''
}

/**
 * Returns true if the server supports this version.
 *
 * @param {String} version
 * @return {Boolean}
 * @api public
 */
exports.isSupportedVersion = function (version) {
  return QUIC_VERSIONS.includes(version)
}

class BaseProtocol {
  constructor (buf) {
    if (!Buffer.isBuffer(buf)) throw new Error('invalid BaseProtocol buffer')
    this[BUF] = buf
  }

  equals (other) {
    return this[BUF].equals(other[BUF])
  }

  get byteLen () {
    return this[BUF].length
  }

  toBuffer () {
    return this[BUF]
  }

  toString () {
    return this[BUF].toString('hex')
  }
}

class ConnectionID extends BaseProtocol {
  constructor (buf) {
    super(buf)
    if (buf.length !== 8) throw new Error('invalid ConnectionID buffer')
    this[VAL] = buf.toString('hex')
  }

  get value () {
    return this[VAL]
  }

  [util.inspect.custom] (depth, options) {
    return `<ConnectionID ${this.toString()}>`
  }

  static fromString (str) {
    return new ConnectionID(Buffer.from(str, 'hex'))
  }

  static random () {
    return new ConnectionID(crypto.randomBytes(8))
  }
}

class PacketNumber extends BaseProtocol {
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

  [util.inspect.custom] (depth, options) {
    return `<PacketNumber ${this.toString()}>`
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

class StreamID extends BaseProtocol {
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

  [util.inspect.custom] (depth, options) {
    return `<StreamID ${this[VAL]}>`
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

class SocketAddress extends BaseProtocol {
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

  [util.inspect.custom] (depth, options) {
    return `<SocketAddress port: ${this.port}, address: ${this.address}, family: ${this.family}>`
  }

  static fromObject (address) {
    if (!isAddress(address)) throw new Error(`invalid SocketAddress object: ${util.inspect(address)}`)

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

class Offset extends BaseProtocol {
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
    else if (value <= MaxOffset) len = 7
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

  [util.inspect.custom] (depth, options) {
    return `<Offset ${this.toString()}>`
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
    else if (value <= MaxOffset) len = 7
    else throw new Error('invalid Offset buffer')

    let buf = Buffer.alloc(len)
    if (value) buf.writeUIntLE(value, 0, len, true)
    return new Offset(buf)
  }
}

function isAddress (address) {
  return address && address.port >= 0 &&
    address.port === Math.floor(address.port) &&
    typeof address.address === 'string' &&
    (address.family === 'IPv4' || address.family === 'IPv6')
}

exports.ConnectionID = ConnectionID
exports.PacketNumber = PacketNumber
exports.StreamID = StreamID
exports.SocketAddress = SocketAddress
exports.Offset = Offset
