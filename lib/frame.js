'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

// const assert = require('assert')
const QuicID = require('./id')
const QuicError = require('./error')
const Visitor = require('./util').Visitor
const allocBuffer = require('./util').allocBuffer
const BUF = Symbol('QuicFrame.buf')
const initBuf = Symbol('QuicFrame.initBuf')

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
// | 1fdooossB | STREAM |
// | 01ntllmmB | ACK |
// | 001xxxxxB | CONGESTION_FEEDBACK |
// -----

class QuicFrame {
  constructor (type) {
    this[BUF] = null
    this.type = type
  }

  get byteLen () {
    this.toBuffer().length
  }

  toBuffer () {
    if (!this[BUF]) this[BUF] = this[initBuf]()
    return this[BUF]
  }

  [initBuf] () {
    throw new Error('method "initBuf" is not implemented')
  }

  static fromBuffer (buf, fromServer) {
    let type = buf.readUInt8(0, true)
    if (type >= 128) return StreamFrame.fromBuffer(buf, fromServer)
    if (type >= 64) return AckFrame.fromBuffer(buf, fromServer)
    if (type >= 32) return CongestionFeedbackFrame.fromBuffer(buf, fromServer)

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
    return allocBuffer(1)
  }

  static fromBuffer () {
    return new PaddingFrame()
  }
}

class ResetStreamFrame extends QuicFrame { // RST_STREAM Frame
  constructor (streamId, offset, error) {
    super(0x01)
    this.streamId = streamId
    this.offset = offset
    this.error = error
  }

  [initBuf] () {
    let buf = allocBuffer(17)
    buf.writeUInt8(this.type)
    this.streamId.toBuffer().copy(buf, 1, 0, 4)
    this.offset.copy(buf, 5, 0, 8)
    this.error.toBuffer().copy(buf, 13, 0, 4)
    return buf
  }

  static fromBuffer (buf) {
    let v = new Visitor(0, 1)
    if (buf[v.start] !== 1 || buf.length < 17) throw new QuicError('INVALID_RST_STREAM_DATA')
    v.walk(4)
    let streamId = new QuicID.StreamId(buf.slice(v.start, v.end))
    v.walk(8)
    let offset = buf.slice(v.start, v.end)
    v.walk(4)
    let error = new QuicError(buf.readUInt32LE(v.start))
    let frame = new ResetStreamFrame(streamId, offset, error)
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
    let buf = allocBuffer(7 + reasonPhraseLen)
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
  constructor (error, lastGoodStreamId) {
    super(0x03)
    this.error = error
    this.streamId = lastGoodStreamId
  }

  [initBuf] () {
    let reasonPhrase = this.error.message
    let reasonPhraseLen = reasonPhrase ? Buffer.byteLength(reasonPhrase) : 0
    let buf = allocBuffer(11 + reasonPhraseLen)
    buf.writeUInt8(this.type)
    this.error.toBuffer().copy(buf, 1, 0, 4)
    this.streamId.toBuffer().copy(buf, 5, 0, 4)
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
    let streamId = new QuicID.StreamId(buf.slice(v.start, v.end))
    v.walk(2)
    let reasonPhraseLen = buf.readUInt16LE(v.start, true)
    if (reasonPhraseLen) {
      v.walk(reasonPhraseLen)
      if (buf.length < v.end) throw new QuicError('INVALID_GOAWAY_DATA')
      error.message = buf.toString('utf8', v.start, v.end)
    }
    let frame = new GoAwayFrame(error, streamId)
    frame[BUF] = buf.slice(0, v.end)
    return frame
  }
}

class WindowUpdateFrame extends QuicFrame { // WINDOW_UPDATE Frame
  constructor (streamId, offset) {
    super(0x04)
    this.streamId = streamId
    this.offset = offset
  }

  [initBuf] () {
    let buf = allocBuffer(13)
    buf.writeUInt8(this.type)
    this.streamId.toBuffer().copy(buf, 1, 0, 4)
    this.offset.copy(buf, 5, 0, 8)
    return buf
  }

  static fromBuffer (buf) {
    let v = new Visitor(0, 1)
    if (buf[v.start] !== 4 || buf.length < 13) throw new QuicError('INVALID_WINDOW_UPDATE_DATA')
    v.walk(4)
    let streamId = new QuicID.StreamId(buf.slice(v.start, v.end))
    v.walk(8)
    let offset = buf.slice(v.start, v.end)
    let frame = new WindowUpdateFrame(streamId, offset)
    frame[BUF] = buf.slice(0, v.end)
    return frame
  }
}

class BlockedFrame extends QuicFrame { // TODO BLOCKED Frame
  constructor (streamId) {
    super(0x05)

    this.streamId = streamId
  }

  static fromBuffer (buf) {

  }
}

class StopWaitingFrame extends QuicFrame { // TODO STOP_WAITING Frame
  constructor (LeastUnackedDelta) {
    super(0x06)

    this.LeastUnackedDelta = LeastUnackedDelta
  }
}

class PingFrame extends QuicFrame { // PING frame
  constructor () {
    super(0x07)
  }

  toBuffer () {
    return new Buffer([0b00000111])
  }

  static fromBuffer (buf) {

  }
}

class StreamFrame extends QuicFrame { // TODO STREAM Frame
  constructor (flag, streamId, offset, data) {
    super(flag)

    this.streamId = streamId
    this.offset = offset
    this.data = data
  }

  static fromBuffer (buf) {

  }
}

class AckFrame extends QuicFrame { // TODO ACK Frame
  constructor (flag, LargestPacketNumber) {
    super(flag)

    this.LargestPacketNumber = LargestPacketNumber
  }

  static fromBuffer (buf) {

  }
}

class CongestionFeedbackFrame extends QuicFrame { // CONGESTION_FEEDBACK Frame
  constructor () {
    super(0b00100000)
  }

  toBuffer () {
    return new Buffer([0b00100000])
  }

  static fromBuffer (buf) {

  }
}

QuicFrame.StreamFrame = StreamFrame
QuicFrame.AckFrame = AckFrame
QuicFrame.StopWaitingFrame = StopWaitingFrame
QuicFrame.WindowUpdateFrame = WindowUpdateFrame
QuicFrame.BlockedFrame = BlockedFrame
QuicFrame.CongestionFeedbackFrame = CongestionFeedbackFrame
QuicFrame.PaddingFrame = PaddingFrame
QuicFrame.ResetStreamFrame = ResetStreamFrame
QuicFrame.PingFrame = PingFrame
QuicFrame.ConnectionCloseFrame = ConnectionCloseFrame
QuicFrame.GoAwayFrame = GoAwayFrame

module.exports = QuicFrame
