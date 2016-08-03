'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

class PublicHeader {
  constructor (version, reset, connectionId, packetNumber, byteLen) {
    this.fromServer = false
    this.flagVersion = !!version
    this.flagReset = !!reset
    this.version = version
    this.connectionId = connectionId
    this.packetNumber = packetNumber
    this.byteLen = byteLen
  }

  toBuffer () {}

  static fromBuffer (buf, fromServer) {
    let start = 1
    let end = 1
    let flag = buf.readUIntLE(0, 1, true)
    if (flag > 127) return null // 0x80 is currently unused, and must be set to 0
    let version = !!(flag & 0b1)
    let reset = !!(flag & 0b10)

    let connectionIdLen = 0
    let connectionIdBuf = null
    switch (flag & 0b1100) {
      case 0b1100:
        connectionIdLen = 8
        break
      case 0b1000:
        connectionIdLen = 4
        break
      case 0b0100:
        connectionIdLen = 1
        break
    }
    if (connectionIdLen) {
      end = start + connectionIdLen
      connectionIdBuf = buf.slice(start, end)
      if (connectionIdBuf.length !== connectionIdLen) return null
      start = end
    }

    if (version) {
      end += 4
      version = buf.slice(start, end)
      if (version.length !== 4) return null
      version = version.toString()
      start = end
    }

    let packetNumberLen = 1
    switch (flag & 0b110000) {
      case 0b110000:
        connectionIdLen = 6
        break
      case 0b100000:
        connectionIdLen = 4
        break
      case 0b010000:
        connectionIdLen = 2
        break
    }

    end = start + packetNumberLen
    let packetNumberBuf = buf.slice(start, end)
    if (packetNumberBuf.length !== packetNumberLen) return null

    return new PublicHeader(version, reset,
      connectionIdBuf && ConnectionId.fromBuffer(connectionIdBuf),
      PacketNumber.fromBuffer(packetNumberBuf), end)
  }
}

class ConnectionId {
  constructor (buf) {
    this.buf = buf
    if (buf.length <= 4) this.id = [buf.readUIntLE(0, buf.length, true)]
    else this.id = [buf.readUIntLE(0, 4, true), buf.readUIntLE(4, 4, true)]
  }

  toBuffer () {
    return this.buf
  }

  equals (other) {
    if (other instanceof ConnectionId) {
      if (this.id[0] !== other.id[0]) return false
      if (this.id[1] && (this.id[1] !== other.id[1])) return false
      return true
    }
    return false
  }

  static fromBuffer (buf) {
    return new ConnectionId(buf)
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

  equals (other) {
    return other instanceof PacketNumber && this.id === other.id
  }

  static fromBuffer (buf) {
    return new PacketNumber(buf)
  }
}

exports.PublicHeader = PublicHeader
