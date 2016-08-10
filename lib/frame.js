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

class Frame {
  constructor (flag) { // TODO
    this.flag = flag
  }

  toBuffer () {
    throw new Error('method "toBuffer" is not implemented')
  }
}

class PaddingFrame extends Frame { // PADDING Frame
  constructor () {
    super(0x00)
  }

  toBuffer () {
    return new Buffer([0x00])
  }
}

class ResetStreamFrame extends Frame { // TODO RST_STREAM Frame
  constructor (streamId, offset, errorCode) {
    super(0x01)

    this.streamId = streamId
    this.offset = offset
    this.errorCode = errorCode
  }
}

class ConnectionCloseFrame extends Frame { // TODO CONNECTION_CLOSE frame
  constructor (errorCode, reasonPhraseLen, reasonPhrase) {
    super(0x02)

    this.errorCode = errorCode
    this.reasonPhraseLen = reasonPhraseLen
    this.reasonPhrase = reasonPhrase
  }
}

class GoAwayFrame extends Frame { // TODO GOAWAY Frame
  constructor (errorCode, lastGoodStreamId, reasonPhraseLen, reasonPhrase) {
    super(0x03)

    this.errorCode = errorCode
    this.lastGoodStreamId = lastGoodStreamId
    this.reasonPhraseLen = reasonPhraseLen
    this.reasonPhrase = reasonPhrase
  }
}

class WindowUpdateFrame extends Frame { // TODO WINDOW_UPDATE Frame
  constructor (streamId, offset) {
    super(0x04)

    this.streamId = streamId
    this.offset = offset
  }
}

class BlockedFrame extends Frame { // TODO BLOCKED Frame
  constructor (streamId) {
    super(0x05)

    this.streamId = streamId
  }
}

class StopWaitingFrame extends Frame { // TODO STOP_WAITING Frame
  constructor (LeastUnackedDelta) {
    super(0x06)

    this.LeastUnackedDelta = LeastUnackedDelta
  }
}

class PingFrame extends Frame { // PING frame
  constructor () {
    super(0x07)
  }

  toBuffer () {
    return new Buffer([0b00000111])
  }
}

class StreamFrame extends Frame { // TODO STREAM Frame
  constructor (flag, streamId, offset, data) {
    super(flag)

    this.streamId = streamId
    this.offset = offset
    this.data = data
  }
}

class AckFrame extends Frame { // TODO ACK Frame
  constructor (flag, LargestPacketNumber) {
    super(flag)

    this.LargestPacketNumber = LargestPacketNumber
  }
}

class CongestionFeedbackFrame extends Frame { // CONGESTION_FEEDBACK Frame
  constructor () {
    super(0b00100000)
  }

  toBuffer () {
    return new Buffer([0b00100000])
  }
}

class QuicTag {
  constructor (name) {
    this.name = name
    this.keys = []
    this.values = {}
  }

  setTag (key, val) {
    if (this.values[key] == null) this.keys.push(key)
    this.values[key] = val
  }

  getTags () {
    return this.values
  }

  toBuffer () {
    let byteLen = 8
    for (let key of this.keys) byteLen += 8 + this.values[key].length

    let buf = allocBuffer(byteLen).fill(0)
    buf.write(this.name, 0, 4)
    buf.writeUIntLE(this.keys.length, 4, 4, true)
    let offset1 = 8
    let offset2 = 0
    let offset3 = offset1 + 8 * this.keys.length
    for (let key of this.keys) {
      let val = this.values[key]
      buf.write(key, offset1, 4)
      offset1 += 4
      offset2 += val.length
      buf.writeUIntLE(offset2, offset1, 4, true)
      offset1 += 4
      val.copy(buf, offset3, 0, val.length)
      offset3 += val.length
    }
    return buf
  }

  static fromBuffer (buf, offset, byteLen) {
    if (offset > 0 && byteLen > 0) buf = buf.slice(offset, byteLen)
    let name = buf.toString('utf8', 0, 4)
    let quicTag = new QuicTag(name)
    let count = buf.readInt32LE(4)
    let offset1 = 8
    let offset2 = offset1 + 8 * count
    let start = offset2
    let end = offset2
    while (count--) {
      let key = buf.toString('utf8', offset1, offset1 + 4)
      offset1 += 4
      end = offset2 + buf.readInt32LE(offset1)
      offset1 += 4
      let val = buf.slice(start, end)
      quicTag.setTag(key, val)
      start = end
    }
    return quicTag
  }
}

exports.Frame = Frame
exports.StreamFrame = StreamFrame
exports.AckFrame = AckFrame
exports.StopWaitingFrame = StopWaitingFrame
exports.WindowUpdateFrame = WindowUpdateFrame
exports.BlockedFrame = BlockedFrame
exports.CongestionFeedbackFrame = CongestionFeedbackFrame
exports.PaddingFrame = PaddingFrame
exports.ResetStreamFrame = ResetStreamFrame
exports.PingFrame = PingFrame
exports.ConnectionCloseFrame = ConnectionCloseFrame
exports.GoAwayFrame = GoAwayFrame
exports.QuicTag = QuicTag
