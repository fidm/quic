'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

// const assert = require('assert')
const QuicID = require('./id')
const QuicError = require('./error')
const Visitor = require('./util').Visitor
const readUFloat16 = require('./util').readUFloat16

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

// PADDING Frame
class PaddingFrame extends QuicFrame {
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

// RST_STREAM Frame
class ResetStreamFrame extends QuicFrame {
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

// CONNECTION_CLOSE frame
class ConnectionCloseFrame extends QuicFrame {
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

// GOAWAY Frame
class GoAwayFrame extends QuicFrame {
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

// WINDOW_UPDATE Frame
class WindowUpdateFrame extends QuicFrame {
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

// BLOCKED Frame
class BlockedFrame extends QuicFrame {
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

// STOP_WAITING Frame
class StopWaitingFrame extends QuicFrame {
  constructor (leastUnackedDelta, packetNumberLen) {
    super(0x06)
    this.delta = leastUnackedDelta
    this.packetNumberLen = packetNumberLen
  }

  [initBuf] () {
    // let packetNumber = this.packetNumber.toBuffer()
    let buf = Buffer.alloc(1 + this.packetNumberLen)
    buf.writeUInt8(this.type)
    buf.writeUIntLE(this.delta, 1, this.packetNumberLen)
    return buf
  }

  toPacketNumber (headerPacketNumber) {
    return QuicID.PacketNumber.fromValue(headerPacketNumber.value - this.delta)
  }

  static fromBuffer (buf, packetNumberLen) {
    if (buf[0] !== 6) throw new QuicError('INVALID_STOP_WAITING_DATA')
    let delta = buf.readIntLE(1, packetNumberLen, false)
    return new StopWaitingFrame(delta, packetNumberLen)
  }
}

// PING frame
class PingFrame extends QuicFrame {
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

// CONGESTION_FEEDBACK Frame
class CongestionFrame extends QuicFrame {
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

// ACK Frame
// https://docs.google.com/document/d/1oWwSevT81d_kIFAm-UQlDxv1yxS2aHP1W1iooLPYhPo/pub
class AckFrame extends QuicFrame {
  constructor () {
    let type = 0b01000000
    super(type)
    this.largestAcked = null // largestPacketNumber
    this.lowestAcked = null // lowestPacketNumber
    // has to be ordered. The ACK range with the highest FirstPacketNumber goes first,
    // the ACK range with the lowest FirstPacketNumber goes last
    this.ackRanges = []
    this.delayTime = 0 // microseconds
    // only for received packets. Will not be modified for received ACKs frames
    this.packetReceivedTime = null
  }

  [initBuf] () {}

  validateAckRanges () {
    if (this.ackRanges.length === 0) {
      return true
    }
    // if there are missing packets, there will always be at least 2 ACK ranges
    if (this.ackRanges.length === 1) {
      return false
    }

    if (this.ackRanges[0].lastPacketNumber !== this.largestAcked.value) {
      return false
    }

    // check the validity of every single ACK range
    let i = 0
    for (let ackRange of this.ackRanges) {
      if (ackRange.firstPacketNumber > ackRange.lastPacketNumber) {
        return false
      }
      // check the consistency for ACK with multiple NACK ranges
      if (!i++) {
        continue
      }
      let lastAckRange = this.ackRanges[i - 1]
      if (lastAckRange.firstPacketNumber <= ackRange.firstPacketNumber) {
        return false
      }
      if (lastAckRange.firstPacketNumber <= (ackRange.lastPacketNumber + 1)) {
        return false
      }
    }
    return true
  }

  static fromBuffer (buf) {
    let type = buf[0]
    if (!QuicFrame.isACKType(type)) throw new QuicError('INVALID_ACK_DATA')

    let frame = new AckFrame()
    let hasMissingRanges = type & 0b00100000
    let largestAckedLen = QuicID.PacketNumber.flagToByteLen((type & 0b1100) >> 2)
    let missingSequenceNumberDeltaLen = (2 * (type & 0b11)) || 1

    let v = new Visitor(1)
    v.walk(largestAckedLen)
    if (buf.length < v.end) throw new QuicError('INVALID_FRAME_DATA')
    frame.largestAcked = new QuicID.PacketNumber(buf.slice(v.start, v.end))

    v.walk(2)
    if (buf.length < v.end) throw new QuicError('INVALID_FRAME_DATA')
    frame.delayTime = readUFloat16(buf, v.start)

    let numAckBlocks = 0
    if (hasMissingRanges) {
      v.walk(1)
      if (buf.length < v.end) throw new QuicError('INVALID_FRAME_DATA')
      numAckBlocks = buf.readUInt8(v.start, true)
    }
    if (hasMissingRanges && numAckBlocks === 0) {
      throw new QuicError('INVALID_FRAME_DATA')
    }
    v.walk(missingSequenceNumberDeltaLen)
    if (buf.length < v.end) throw new QuicError('INVALID_FRAME_DATA')
    let ackBlockLength = buf.readUIntLE(v.start, missingSequenceNumberDeltaLen, true)
    let largestAcked = frame.largestAcked.value
    if (largestAcked > 0 && (ackBlockLength < 1 || (ackBlockLength > largestAcked))) {
      throw new QuicError('INVALID_FRAME_DATA')
    }

    if (hasMissingRanges) {
      let ackRange = new AckRange(
        QuicID.PacketNumber.fromValue(largestAcked - ackBlockLength + 1).value,
        frame.LargestAcked.value
      )
      frame.ackRanges.push(ackRange)

      let gap = 0
      let inLongBlock = false
      let lastRangeComplete = false
      for (let i = 0; i < numAckBlocks; i++) {
        v.walk(1)
        if (buf.length < v.end) throw new QuicError('INVALID_FRAME_DATA')
        gap = buf.readUInt8(v.start, true)

        v.walk(missingSequenceNumberDeltaLen)
        if (buf.length < v.end) throw new QuicError('INVALID_FRAME_DATA')
        ackBlockLength = buf.readUIntLE(v.start, missingSequenceNumberDeltaLen, true)

        if (inLongBlock) {
          frame.ackRanges[frame.ackRanges.length - 1].firstPacketNumber -= gap + ackBlockLength
          frame.ackRanges[frame.ackRanges.length - 1].lastPacketNumber -= gap
        } else {
          lastRangeComplete = false
          ackRange = new AckRange(
            0,
            frame.AckRanges[frame.AckRanges.length - 1].firstPacketNumber - gap - 1
          )
          ackRange.firstPacketNumber = ackRange.lastPacketNumber - ackBlockLength + 1
          frame.ackRanges.push(ackRange)
        }

        if (ackBlockLength > 0) {
          lastRangeComplete = true
        }
        inLongBlock = (ackBlockLength === 0)
      }

      // if the last range was not complete, firstPacketNumber and lastPacketNumber make no sense
      // remove the range from frame.ackRanges
      if (!lastRangeComplete) {
        frame.ackRanges = frame.ackRanges.slice(0, -1)
      }
      frame.lowestAcked = QuicID.PacketNumber.fromValue(
        frame.ackRanges[frame.ackRanges.length - 1].firstPacketNumber)
    } else {
      if (frame.largestAcked.value === 0) {
        frame.lowestAcked = QuicID.PacketNumber.fromValue(0)
      } else {
        frame.lowestAcked = QuicID.PacketNumber.fromValue(largestAcked - ackBlockLength + 1)
      }
    }

    if (!frame.validateAckRanges()) {
      throw new QuicError('INVALID_FRAME_DATA')
    }

    v.walk(1)
    if (buf.length < v.end) throw new QuicError('INVALID_FRAME_DATA')
    let numTimestamp = buf.readUInt8(v.start, true)
    if (numTimestamp > 0) {
      // Delta Largest acked, TODO
      v.walk(1)
      if (buf.length < v.end) throw new QuicError('INVALID_FRAME_DATA')
      // First Timestamp, TODO
      v.walk(4)
      if (buf.length < v.end) throw new QuicError('INVALID_FRAME_DATA')
      buf.readUInt32LE(v.start, true)

      for (let i = 0; i < numTimestamp - 1; i++) {
        // Delta Largest acked
        v.walk(1)
        if (buf.length < v.end) throw new QuicError('INVALID_FRAME_DATA')
        // Time Since Previous Timestamp
        v.walk(4)
        if (buf.length < v.end) throw new QuicError('INVALID_FRAME_DATA')
        buf.readUInt16LE(v.start, true)
      }
    }

    return frame
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

class AckRange {
  constructor (firstPacketNumber, lastPacketNumber) {
    this.firstPacketNumber = firstPacketNumber // number
    this.lastPacketNumber = lastPacketNumber
  }
}

// class PacketsTimestamp {
//   constructor () {
//     this.timestamps = []
//   }
//   toBuffer () {}
// }

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
