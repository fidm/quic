'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

// const assert = require('assert')
const allocBuffer = require('./util').allocBuffer

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
  constructor (flag) {
    this.flag = flag
  }

  toBuffer () {
    throw new Error('method "toBuffer" is not implemented')
  }
}

class PaddingFrame extends QuicFrame { // PADDING Frame
  constructor () {
    super(0x00)
  }

  toBuffer () {
    let buf = allocBuffer(1)
    buf.writeUInt8(this.flag)
    return buf
  }
}

class ResetStreamFrame extends QuicFrame {
  constructor (streamId, offset, error) {
    super(0x01)

    this.streamId = streamId
    this.offset = offset
    this.error = error
  }

  toBuffer () {
    let buf = allocBuffer(17)
    buf.writeUInt8(this.flag)
    this.streamId.toBuffer().copy(buf, 1, 0, 4)
    this.offset.copy(buf, 5, 0, 8)
    this.error.toBuffer().copy(buf, 13, 0, 4)
    return buf
  }
}

class ConnectionCloseFrame extends QuicFrame { // TODO CONNECTION_CLOSE frame
  constructor (errorCode, reasonPhraseLen, reasonPhrase) {
    super(0x02)

    this.errorCode = errorCode
    this.reasonPhraseLen = reasonPhraseLen
    this.reasonPhrase = reasonPhrase
  }
}

class GoAwayFrame extends QuicFrame { // TODO GOAWAY Frame
  constructor (errorCode, lastGoodStreamId, reasonPhraseLen, reasonPhrase) {
    super(0x03)

    this.errorCode = errorCode
    this.lastGoodStreamId = lastGoodStreamId
    this.reasonPhraseLen = reasonPhraseLen
    this.reasonPhrase = reasonPhrase
  }
}

class WindowUpdateFrame extends QuicFrame { // TODO WINDOW_UPDATE Frame
  constructor (streamId, offset) {
    super(0x04)

    this.streamId = streamId
    this.offset = offset
  }
}

class BlockedFrame extends QuicFrame { // TODO BLOCKED Frame
  constructor (streamId) {
    super(0x05)

    this.streamId = streamId
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
}

class StreamFrame extends QuicFrame { // TODO STREAM Frame
  constructor (flag, streamId, offset, data) {
    super(flag)

    this.streamId = streamId
    this.offset = offset
    this.data = data
  }
}

class AckFrame extends QuicFrame { // TODO ACK Frame
  constructor (flag, LargestPacketNumber) {
    super(flag)

    this.LargestPacketNumber = LargestPacketNumber
  }
}

class CongestionFeedbackFrame extends QuicFrame { // CONGESTION_FEEDBACK Frame
  constructor () {
    super(0b00100000)
  }

  toBuffer () {
    return new Buffer([0b00100000])
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
