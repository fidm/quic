'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

// const assert = require('assert')
const QuicID = require('./id')
const QuicError = require('./error')
const Visitor = require('./util').Visitor

const BUF = Symbol('QuicFrame.buf')
const initBuf = Symbol('QuicFrame.initBuf')

class QuicFrame {
  constructor (type) {
    this[BUF] = null
    this.type = type
  }

  get byteLen () {
    return this.toBuffer().length
  }

  toBuffer () {
    if (!this[BUF]) this[BUF] = this[initBuf]()
    return this[BUF]
  }

  [initBuf] () {
    throw new Error('method "initBuf" is not implemented')
  }

  // Frame Types
  // | Type­field value | Control Frame­type |
  // -----
  // | 00000000B (0x00) | PADDING |
  // | 00000001B (0x01) | RST_STREAM |
  // | 00000010B (0x02) | CONNECTION_CLOSE |
  // | 00000011B (0x03) | GOAWAY |
  // | 00000100B (0x04) | WINDOW_UPDATE |
  // | 00000101B (0x05) | BLOCKED |
  // | 00000110B (0x06) | STOP_WAITING |
  // | 00000111B (0x07) | PING |
  // -----
  // | 001xxxxxB | CONGESTION_FEEDBACK |
  // | 01ntllmmB | ACK |
  // | 1fdooossB | STREAM |
  // -----

  static isCongestionType (type) {
    return (type & 0b11100000) === 0b00100000
  }

  static isACKType (type) {
    return (type & 0b11000000) === 0b01000000
  }

  static isStreamType (type) {
    return type > 0b10000000
  }

  static fromBuffer (buf, fromServer) {
    let type = buf.readUInt8(0, true)
    if (type >= 128) return StreamFrame.fromBuffer(buf, fromServer)
    if (type >= 64) return AckFrame.fromBuffer(buf, fromServer)
    if (type >= 32) return CongestionFrame.fromBuffer(buf, fromServer)

    switch (type) {
      case 0:
        return PaddingFrame.fromBuffer(buf)
      case 1:
        return ResetStreamFrame.fromBuffer(buf)
      case 2:
        return ConnectionCloseFrame.fromBuffer(buf)
      case 3:
        return GoAwayFrame.fromBuffer(buf)
      case 4:
        return WindowUpdateFrame.fromBuffer(buf)
      case 5:
        return BlockedFrame.fromBuffer(buf)
      case 6:
        return StopWaitingFrame.fromBuffer(buf)
      case 7:
        return PingFrame.fromBuffer(buf)
      default:
        throw new QuicError('INVALID_FRAME_DATA')
    }
  }
}

class PaddingFrame extends QuicFrame { // PADDING Frame
  constructor () {
    super(0x00)
  }

  [initBuf] () {
    return Buffer.alloc(1)
  }

  static fromBuffer () {
    return new PaddingFrame()
  }
}

class ResetStreamFrame extends QuicFrame { // RST_STREAM Frame
  constructor (streamID, offset, error) {
    super(0x01)
    this.streamID = streamID
    this.offset = offset
    this.error = error
  }

  [initBuf] () {
    let buf = Buffer.alloc(17)
    buf.writeUInt8(this.type)
    this.streamID.toBuffer().copy(buf, 1, 0, 4)
    this.offset.toFullBuffer().copy(buf, 5, 0, 8)
    this.error.toBuffer().copy(buf, 13, 0, 4)
    return buf
  }

  static fromBuffer (buf) {
    let v = new Visitor(0, 1)
    if (buf[v.start] !== 1 || buf.length < 17) throw new QuicError('INVALID_RST_STREAM_DATA')
    v.walk(4)
    let streamID = new QuicID.StreamID(buf.slice(v.start, v.end))
    v.walk(8)
    let offset = new QuicID.Offset(buf.slice(v.start, v.end))
    v.walk(4)
    let error = new QuicError(buf.readUInt32LE(v.start))
    let frame = new ResetStreamFrame(streamID, offset, error)
    frame[BUF] = buf.slice(0, v.end)
    return frame
  }
}

class ConnectionCloseFrame extends QuicFrame { // CONNECTION_CLOSE frame
  constructor (error) {
    super(0x02)
    this.error = error
  }

  [initBuf] () {
    let reasonPhrase = this.error.message
    let reasonPhraseLen = reasonPhrase ? Buffer.byteLength(reasonPhrase) : 0
    let buf = Buffer.alloc(7 + reasonPhraseLen)
    buf.writeUInt8(this.type)
    this.error.toBuffer().copy(buf, 1, 0, 4)
    buf.writeUInt16LE(reasonPhraseLen, 5, true)
    if (reasonPhrase) buf.write(reasonPhrase, 7, reasonPhraseLen)
    return buf
  }

  static fromBuffer (buf) {
    let v = new Visitor(0, 1)
    if (buf[v.start] !== 2 || buf.length < 7) throw new QuicError('INVALID_CONNECTION_CLOSE_DATA')
    v.walk(4)
    let error = new QuicError(buf.readUInt32LE(v.start))
    v.walk(2)
    let reasonPhraseLen = buf.readUInt16LE(v.start, true)
    if (reasonPhraseLen) {
      v.walk(reasonPhraseLen)
      if (buf.length < v.end) throw new QuicError('INVALID_CONNECTION_CLOSE_DATA')
      error.message = buf.toString('utf8', v.start, v.end)
    }
    let frame = new ConnectionCloseFrame(error)
    frame[BUF] = buf.slice(0, v.end)
    return frame
  }
}

class GoAwayFrame extends QuicFrame { // GOAWAY Frame
  constructor (error, lastGoodStreamID) {
    super(0x03)
    this.error = error
    this.streamID = lastGoodStreamID
  }

  [initBuf] () {
    let reasonPhrase = this.error.message
    let reasonPhraseLen = reasonPhrase ? Buffer.byteLength(reasonPhrase) : 0
    let buf = Buffer.alloc(11 + reasonPhraseLen)
    buf.writeUInt8(this.type)
    this.error.toBuffer().copy(buf, 1, 0, 4)
    this.streamID.toBuffer().copy(buf, 5, 0, 4)
    buf.writeUInt16LE(reasonPhraseLen, 9, true)
    if (reasonPhrase) buf.write(reasonPhrase, 11)
    return buf
  }

  static fromBuffer (buf) {
    let v = new Visitor(0, 1)
    if (buf[v.start] !== 3 || buf.length < 11) throw new QuicError('INVALID_GOAWAY_DATA')
    v.walk(4)
    let error = new QuicError(buf.readUInt32LE(v.start))
    v.walk(4)
    let streamID = new QuicID.StreamID(buf.slice(v.start, v.end))
    v.walk(2)
    let reasonPhraseLen = buf.readUInt16LE(v.start, true)
    if (reasonPhraseLen) {
      v.walk(reasonPhraseLen)
      if (buf.length < v.end) throw new QuicError('INVALID_GOAWAY_DATA')
      error.message = buf.toString('utf8', v.start, v.end)
    }
    let frame = new GoAwayFrame(error, streamID)
    frame[BUF] = buf.slice(0, v.end)
    return frame
  }
}

class WindowUpdateFrame extends QuicFrame { // WINDOW_UPDATE Frame
  constructor (streamID, offset) {
    super(0x04)
    this.streamID = streamID
    this.offset = offset
  }

  [initBuf] () {
    let buf = Buffer.alloc(13)
    buf.writeUInt8(this.type)
    this.streamID.toBuffer().copy(buf, 1, 0, 4)
    this.offset.toFullBuffer().copy(buf, 5, 0, 8)
    return buf
  }

  static fromBuffer (buf) {
    let v = new Visitor(0, 1)
    if (buf[v.start] !== 4 || buf.length < 13) throw new QuicError('INVALID_WINDOW_UPDATE_DATA')
    v.walk(4)
    let streamID = new QuicID.StreamID(buf.slice(v.start, v.end))
    v.walk(8)
    let offset = new QuicID.Offset(buf.slice(v.start, v.end))
    let frame = new WindowUpdateFrame(streamID, offset)
    frame[BUF] = buf.slice(0, v.end)
    return frame
  }
}

class BlockedFrame extends QuicFrame { // BLOCKED Frame
  constructor (streamID) {
    super(0x05)
    this.streamID = streamID
  }

  [initBuf] () {
    let buf = Buffer.alloc(5)
    buf.writeUInt8(this.type)
    this.streamID.toBuffer().copy(buf, 1, 0, 4)
    return buf
  }

  static fromBuffer (buf) {
    let v = new Visitor(0, 1)
    if (buf[v.start] !== 5 || buf.length !== 5) throw new QuicError('INVALID_BLOCKED_DATA')
    v.walk(4)
    let streamID = new QuicID.StreamID(buf.slice(v.start, v.end))
    let frame = new BlockedFrame(streamID)
    frame[BUF] = buf.slice(0, v.end)
    return frame
  }
}

class StopWaitingFrame extends QuicFrame { // STOP_WAITING Frame
  constructor (LeastUnackedDelta) {
    super(0x06)
    this.packetNumber = LeastUnackedDelta
  }

  [initBuf] () {
    let packetNumber = this.packetNumber.toBuffer()
    let buf = Buffer.alloc(1 + packetNumber.length)
    buf.writeUInt8(this.type)
    packetNumber.copy(buf, 1, 0, packetNumber.length)
    return buf
  }

  static fromBuffer (buf, packetNumberLen) {
    let v = new Visitor(0, 1)
    if (buf[v.start] !== 6) throw new QuicError('INVALID_STOP_WAITING_DATA')
    v.walk(packetNumberLen)
    let packetNumber = new QuicID.PacketNumber(buf.slice(v.start, v.end))
    if (packetNumber.byteLen !== packetNumberLen) {
      throw new QuicError('INVALID_STOP_WAITING_DATA')
    }
    let frame = new StopWaitingFrame(packetNumber)
    frame[BUF] = buf.slice(0, v.end)
    return frame
  }
}

class PingFrame extends QuicFrame { // PING frame
  constructor () {
    super(0x07)
  }

  [initBuf] () {
    let buf = Buffer.alloc(1)
    buf.writeUInt8(this.type)
    return buf
  }

  static fromBuffer (buf) {
    return new PingFrame()
  }
}

class CongestionFrame extends QuicFrame { // CONGESTION_FEEDBACK Frame
  constructor () {
    super(0b00100000)
  }

  [initBuf] () {
    let buf = Buffer.alloc(1)
    buf.writeUInt8(this.type)
    return buf
  }

  static fromBuffer (buf) {
    if (!QuicFrame.isCongestionType(buf[0])) throw new QuicError('INVALID_FRAME_DATA')
    return new CongestionFrame()
  }
}

class AckFrame extends QuicFrame { // TODO ACK Frame
  constructor (LargestPacketNumber) {
    let type = 0b01000000
    super(type)
    this.LargestPacketNumber = LargestPacketNumber
  }

  static fromBuffer (buf) {
    if (!QuicFrame.isACKType(buf[0])) throw new QuicError('INVALID_ACK_DATA')
  }
}

class StreamFrame extends QuicFrame { // STREAM Frame
  constructor (streamID, offset, data, isFIN) {
    let type = isFIN ? 0b11000000 : 0b10000000
    if (!data || !data.length) data = null
    if (data) type |= 0b00100000
    type |= offset.flagBits << 2
    type |= streamID.flagBits
    super(type)
    this.streamID = streamID
    this.offset = offset
    this.isFIN = !!isFIN
    this.data = data || null
  }

  [initBuf] () {
    let streamLen = this.streamID.byteLen
    let offsetLen = this.offset.byteLen
    let dataLen = this.data ? this.data.length : 0
    let buf = Buffer.alloc(1 + streamLen + offsetLen + (dataLen ? (dataLen + 2) : 0))
    let v = new Visitor(0, 1)
    buf.writeUInt8(this.type)
    v.walk(streamLen)
    this.streamID.toBuffer().copy(buf, v.start, 0, streamLen)
    v.walk(offsetLen)
    this.offset.toBuffer().copy(buf, v.start, 0, offsetLen)
    if (dataLen) {
      v.walk(2)
      buf.writeUInt16LE(dataLen, v.start, true)
      v.walk(dataLen)
      this.data.copy(buf, v.start, 0, dataLen)
    }
    return buf
  }

  static fromBuffer (buf) {
    let type = buf[0]
    if (!QuicFrame.isStreamType(type)) throw new QuicError('INVALID_STREAM_DATA')

    let isFIN = type & 0b1000000
    let dataLen = type & 0b100000
    let offsetLen = QuicID.Offset.flagToByteLen((type & 0b11100) >> 2)
    let streamLen = QuicID.StreamID.flagToByteLen(type & 0b11)

    let v = new Visitor(1)
    let data = null
    v.walk(streamLen)
    if (buf.length < v.end) throw new QuicError('INVALID_STREAM_DATA')
    let streamID = new QuicID.StreamID(buf.slice(v.start, v.end))

    v.walk(offsetLen)
    if (buf.length < v.end) throw new QuicError('INVALID_STREAM_DATA')
    let offset = new QuicID.Offset(buf.slice(v.start, v.end))

    if (dataLen) {
      v.walk(2)
      if (buf.length < v.end) throw new QuicError('INVALID_STREAM_DATA')
      dataLen = buf.readUInt16LE(v.start, true)
      v.walk(dataLen)
      if (buf.length < v.end) throw new QuicError('INVALID_STREAM_DATA')
      data = buf.slice(v.start, v.end)
    }

    let frame = new StreamFrame(streamID, offset, data, isFIN)
    frame[BUF] = buf.slice(0, v.end)
    return frame
  }
}

QuicFrame.PaddingFrame = PaddingFrame
QuicFrame.ResetStreamFrame = ResetStreamFrame
QuicFrame.ConnectionCloseFrame = ConnectionCloseFrame
QuicFrame.GoAwayFrame = GoAwayFrame
QuicFrame.WindowUpdateFrame = WindowUpdateFrame
QuicFrame.BlockedFrame = BlockedFrame
QuicFrame.StopWaitingFrame = StopWaitingFrame
QuicFrame.PingFrame = PingFrame
QuicFrame.CongestionFrame = CongestionFrame
QuicFrame.AckFrame = AckFrame
QuicFrame.StreamFrame = StreamFrame

module.exports = QuicFrame
