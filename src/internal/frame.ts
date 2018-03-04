'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

import { QuicError, QuicStreamError } from './error'
import { PacketNumber, Offset, StreamID } from './protocol'
import { BufferVisitor, readUFloat16, writeUFloat16 } from './common'

// Frame Types
// | Type­field value | Control Frame­type |
//
// ----- Regular Frame Types
// | 00000000B (0x00) | PADDING |
// | 00000001B (0x01) | RST_STREAM |
// | 00000010B (0x02) | CONNECTION_CLOSE |
// | 00000011B (0x03) | GOAWAY |
// | 00000100B (0x04) | WINDOW_UPDATE |
// | 00000101B (0x05) | BLOCKED |
// | 00000110B (0x06) | STOP_WAITING |
// | 00000111B (0x07) | PING |
//
// ----- Special Frame Types
// | 001xxxxxB | CONGESTION_FEEDBACK |
// | 01ntllmmB | ACK |
// | 1fdooossB | STREAM |
// -----

export function isCongestionType (flag: number): boolean {
  return (flag & 0b11100000) === 0b00100000
}

export function isACKType (flag: number): boolean {
  return (flag & 0b11000000) === 0b01000000
}

export function isStreamType (flag: number): boolean {
  return flag > 0b10000000
}

export function parseFrame (bufv: BufferVisitor, headerPacketNumber: PacketNumber): Frame {
  bufv.v.walk(0) // align start and end
  let type = bufv.readUInt8(bufv.v.start, true)
  if (type >= 128) return StreamFrame.fromBuffer(bufv)
  if (type >= 64) return AckFrame.fromBuffer(bufv)
  if (type >= 32) return CongestionFeedbackFrame.fromBuffer(bufv)

  switch (type) {
    case 0:
      return PaddingFrame.fromBuffer(bufv)
    case 1:
      return RstStreamFrame.fromBuffer(bufv)
    case 2:
      return ConnectionCloseFrame.fromBuffer(bufv)
    case 3:
      return GoAwayFrame.fromBuffer(bufv)
    case 4:
      return WindowUpdateFrame.fromBuffer(bufv)
    case 5:
      return BlockedFrame.fromBuffer(bufv)
    case 6:
      return StopWaitingFrame.fromBuffer(bufv, headerPacketNumber)
    case 7:
      return PingFrame.fromBuffer(bufv)
    default:
      throw new QuicError('QUIC_INVALID_FRAME_DATA')
  }
}

/** Frame representing a QUIC frame. */
export abstract class Frame {
  type: number
  name: string
  constructor (type: number, name: string) {
    this.type = type
    this.name = name
  }

  abstract byteLen (): number

  abstract writeTo (bufv: BufferVisitor): BufferVisitor

  static fromBuffer (_bufv: BufferVisitor, _headerPacketNumber?: PacketNumber): Frame {
    throw new Error(`class method "fromBuffer" is not implemented`)
  }
}

/** StreamFrame representing a QUIC STREAM frame. */
export class StreamFrame extends Frame {
  // STREAM Frame
  //
  // The STREAM frame is used to both implicitly create a stream and to send data on it, and is as follows:
  // --- src
  //      0        1       …               SLEN
  // +--------+--------+--------+--------+--------+
  // |Type (8)| Stream ID (8, 16, 24, or 32 bits) |
  // |        |    (Variable length SLEN bytes)   |
  // +--------+--------+--------+--------+--------+
  //
  //   SLEN+1  SLEN+2     …                                         SLEN+OLEN
  // +--------+--------+--------+--------+--------+--------+--------+--------+
  // |   Offset (0, 16, 24, 32, 40, 48, 56, or 64 bits) (variable length)    |
  // |                    (Variable length: OLEN  bytes)                     |
  // +--------+--------+--------+--------+--------+--------+--------+--------+
  //
  //   SLEN+OLEN+1   SLEN+OLEN+2
  // +-------------+-------------+
  // | Data length (0 or 16 bits)|
  // |  Optional(maybe 0 bytes)  |
  // +------------+--------------+
  // ---
  //
  // The fields in the STREAM frame header are as follows:
  // * Frame Type: The Frame Type byte is an 8-bit value containing various flags (1fdooossB):
  //   - The leftmost bit must be set to 1 indicating that this is a STREAM frame.
  //   - The 'f' bit is the FIN bit. When set to 1, this bit indicates the sender is done sending on this stream and wishes to "half-close" (described in more detail later.)
  //   - The 'd' bit indicates whether a Data Length is present in the STREAM header. When set to 0, this field indicates that the STREAM frame extends to the end of the Packet.
  //   - The next three 'ooo' bits encode the length of the Offset header field as 0, 16, 24, 32, 40, 48, 56, or 64 bits long.
  //   - The next two 'ss' bits encode the length of the Stream ID header field as 8, 16, 24, or 32 bits long.
  // * Stream ID: A variable-sized unsigned ID unique to this stream.
  // * Offset: A variable-sized unsigned number specifying the byte offset in the stream for this block of data.
  // * Data length: An optional 16-bit unsigned number specifying the length of the data in this stream frame. The option to omit the length should only be used when the packet is a "full-sized" Packet, to avoid the risk of corruption via padding.
  //
  // A stream frame must always have either non-zero data length or the FIN bit set.

  streamID: StreamID
  offset: Offset
  data: Buffer | null
  isFIN: boolean
  constructor (streamID: StreamID, offset: Offset, data: Buffer | null = null, isFIN: boolean = false) {
    super(0b10000000, 'STREAM')

    this.streamID = streamID
    this.offset = offset
    if (!isFIN && (!Buffer.isBuffer(data) || data.length === 0)) {
      throw new QuicError('QUIC_INVALID_STREAM_DATA')
    }
    this.data = data
    this.isFIN = isFIN || data == null || data.length === 0
  }

  byteLen (): number {
    let dataLen = this.data ? this.data.length : 0
    return 1 + this.streamID.byteLen() + this.offset.byteLen() + (dataLen ? (dataLen + 2) : 0)
  }

  writeTo (bufv: BufferVisitor): BufferVisitor {
    if (this.isFIN) this.type |= 0b1000000
    if (this.data != null) this.type |= 0b00100000
    this.type |= this.offset.flagBits() << 2
    this.type |= this.streamID.flagBits()

    bufv.v.walk(1)
    bufv.writeUInt8(this.type, bufv.v.start)
    this.streamID.writeTo(bufv)
    this.offset.writeTo(bufv)

    if (this.data) {
      bufv.v.walk(2)
      bufv.writeUInt16LE(this.data.length, bufv.v.start, true)
      bufv.v.walk(this.data.length)
      this.data.copy(bufv, bufv.v.start, 0, this.data.length)
    }
    return bufv
  }

  static fromBuffer (bufv: BufferVisitor): StreamFrame {
    bufv.v.walk(1)
    let type = bufv[bufv.v.start]
    if (!isStreamType(type)) throw new QuicError('QUIC_INVALID_STREAM_DATA')

    let isFIN = !!(type & 0b1000000)
    let streamID = StreamID.fromBuffer(bufv, StreamID.flagToByteLen(type & 0b11))
    let offset = Offset.fromBuffer(bufv, Offset.flagToByteLen((type & 0b11100) >> 2))

    let data = null
    if ((type & 0b100000) > 0) {
      bufv.v.walk(2)
      if (bufv.length < bufv.v.end) throw new QuicError('QUIC_INVALID_STREAM_DATA')
      bufv.v.walk(bufv.readUInt16LE(bufv.v.start, true))
      if (bufv.length < bufv.v.end) throw new QuicError('QUIC_INVALID_STREAM_DATA')
      data = bufv.slice(bufv.v.start, bufv.v.end)
    }

    let frame = new StreamFrame(streamID, offset, data, isFIN)
    frame.type = type
    return frame
  }
}

/** AckRange representing a range for ACK. */
export class AckRange {
  firstNum: number
  lastNum: number
  constructor (firstPacketNumberValue: number, lastPacketNumberValue: number) {
    this.firstNum = firstPacketNumberValue // PacketNumber value
    this.lastNum = lastPacketNumberValue
  }
}

/** AckFrame representing a QUIC ACK frame. */
export class AckFrame extends Frame {
  // ACK Frame
  //
  // Section Offsets
  // 0: Start of the ack frame.
  // T: Byte offset of the start of the timestamp section.
  // A: Byte offset of the start of the ack block section.
  // N: Length in bytes of the largest acked.
  //
  // --- src
  //      0                            1  => N                     N+1 => A(aka N + 3)
  // +---------+-------------------------------------------------+--------+--------+
  // |   Type  |                   Largest Acked                 |  Largest Acked  |
  // |   (8)   |    (8, 16, 32, or 48 bits, determined by ll)    | Delta Time (16) |
  // |01nullmm |                                                 |                 |
  // +---------+-------------------------------------------------+--------+--------+
  //
  //      A             A + 1  ==>  A + N
  // +--------+----------------------------------------+
  // | Number |             First Ack                  |
  // |Blocks-1|           Block Length                 |
  // | (opt)  |(8, 16, 32 or 48 bits, determined by mm)|
  // +--------+----------------------------------------+
  //
  //   A + N + 1                A + N + 2  ==>  T(aka A + 2N + 1)
  // +------------+-------------------------------------------------+
  // | Gap to next|              Ack Block Length                   |
  // | Block (8)  |   (8, 16, 32, or 48 bits, determined by mm)     |
  // | (Repeats)  |       (repeats Number Ranges times)             |
  // +------------+-------------------------------------------------+
  //
  //      T        T+1             T+2                 (Repeated Num Timestamps)
  // +----------+--------+---------------------+ ...  --------+------------------+
  // |   Num    | Delta  |     Time Since      |     | Delta  |       Time       |
  // |Timestamps|Largest |    Largest Acked    |     |Largest |  Since Previous  |
  // |   (8)    | Acked  |      (32 bits)      |     | Acked  |Timestamp(16 bits)|
  // +----------+--------+---------------------+     +--------+------------------+
  // ---
  //
  // The fields in the ACK frame are as follows:
  // * Frame Type: The Frame Type byte is an 8-bit value containing various flags (01nullmmB).
  //   - The first two bits must be set to 01 indicating that this is an ACK frame.
  //   - The 'n' bit indicates whether the frame has more than 1 ack range.
  //   - The 'u' bit is unused.
  //   - The two 'll' bits encode the length of the Largest Observed field as 1, 2, 4, or 6 bytes long.
  //   - The two 'mm' bits encode the length of the Missing Packet Sequence Number Delta field as 1, 2, 4, or 6 bytes long.
  // * Largest Acked: A variable-sized unsigned value representing the largest packet number the peer has observed.
  // * Largest Acked Delta Time: A 16-bit unsigned float with 11 explicit bits of mantissa and 5 bits of explicit exponent, specifying the time elapsed in microseconds from when largest acked was received until this Ack frame was sent. The bit format is loosely modeled after IEEE 754. For example, 1 microsecond is represented as 0x1, which has an exponent of zero, presented in the 5 high order bits, and mantissa of 1, presented in the 11 low order bits. When the explicit exponent is greater than zero, an implicit high-order 12th bit of 1 is assumed in the mantissa. For example, a floating value of 0x800 has an explicit exponent of 1, as well as an explicit mantissa of 0, but then has an effective mantissa of 4096 (12th bit is assumed to be 1). Additionally, the actual exponent is one-less than the explicit exponent, and the value represents 4096 microseconds. Any values larger than the representable range are clamped to 0xFFFF.
  // * Ack Block Section:
  //   - Num Blocks: An optional 8-bit unsigned value specifying one less than the number of ack blocks. Only present if the 'n' flag bit is 1.
  //   - Ack block length: A variable-sized packet number delta. For the first missing packet range, the ack block starts at largest acked. For the first ack block, the length of the ack block is 1 + this value.  For subsequent ack blocks, it is the length of the ack block.  For non-first blocks, a value of 0 indicates more than 256 packets in a row were lost.
  //   - Gap to next block: An 8-bit unsigned value specifying the number of packets between ack blocks.
  // * Timestamp Section:
  //   - Num Timestamp: An 8-bit unsigned value specifying the number of timestamps that are included in this ack frame. There will be this many pairs of <packet number, timestamp> following in the timestamps.
  //   - Delta Largest Observed: An 8-bit unsigned value specifying the packet number delta from the first timestamp to the largest observed. Therefore, the packet number is the largest observed minus the delta largest observed.
  //   - First Timestamp: A 32-bit unsigned value specifying the time delta in microseconds, from the beginning of the connection of the arrival of the packet specified by Largest Observed minus Delta Largest Observed.
  //   - Delta Largest Observed (Repeated): (Same as above.)
  //   - Time Since Previous Timestamp (Repeated): A 16-bit unsigned value specifying delta from the previous timestamp. It is encoded in the same format as the Ack Delay Time.
  //
  largestAcked: number
  lowestAcked: number
  ackRanges: AckRange[]
  delayTime: number
  packetReceivedTime: any
  constructor () {
    super(0b01000000, 'ACK')

    this.largestAcked = 0 // largest PacketNumber Value
    this.lowestAcked = 0 // lowest PacketNumber Value
    // has to be ordered. The ACK range with the highest firstNum goes first, the ACK range with the lowest firstNum goes last
    this.ackRanges = []
    this.delayTime = 0 // microseconds
    // time when the LargestAcked was received, this field Will not be set for received ACKs frames
    this.packetReceivedTime = null // should be process.hrtime()
  }

  hasMissingRanges (): boolean {
    return this.ackRanges.length > 0
  }

  validateAckRanges (): boolean {
    if (this.ackRanges.length === 0) {
      return true
    }
    // if there are missing packets, there will always be at least 2 ACK ranges
    if (this.ackRanges.length === 1) {
      return false
    }

    if (this.ackRanges[0].lastNum !== this.largestAcked) {
      return false
    }

    // check the validity of every single ACK range
    for (let ackRange of this.ackRanges) {
      if (ackRange.firstNum > ackRange.lastNum || ackRange.firstNum <= 0) {
        return false
      }
    }

    // check the consistency for ACK with multiple NACK ranges
    for (let i = 1, l = this.ackRanges.length; i < l; i++) {
      let lastAckRange = this.ackRanges[i - 1]
      if (lastAckRange.firstNum <= this.ackRanges[i].firstNum) {
        return false
      }
      if (lastAckRange.firstNum <= (this.ackRanges[i].lastNum + 1)) {
        return false
      }
    }
    return true
  }

  numWritableNackRanges (): number {
    if (this.ackRanges.length === 0) {
      return 0
    }

    let numRanges = 0
    for (let i = 1, l = this.ackRanges.length; i < l; i++) {
      let lastAckRange = this.ackRanges[i - 1]
      let gap = lastAckRange.firstNum - this.ackRanges[i].lastNum - 1
      let rangeLength = 1 + Math.floor(gap / 0xff)

      if (gap % 0xff === 0) rangeLength--
      if (numRanges + rangeLength < 0xff) numRanges += rangeLength
      else break
    }

    return numRanges + 1
  }

  getMissingNumberDeltaFlagBits (): number {
    let maxRangeLength = 0

    if (this.hasMissingRanges()) {
      for (let ackRange of this.ackRanges) {
        let rangeLength = ackRange.lastNum - ackRange.firstNum + 1
        if (rangeLength > maxRangeLength) {
          maxRangeLength = rangeLength
        }
      }
    } else {
      maxRangeLength = this.largestAcked - this.lowestAcked + 1
    }

    if (maxRangeLength <= 0xff) return 0
    if (maxRangeLength <= 0xffff) return 1
    if (maxRangeLength <= 0xffffff) return 2
    return 3
  }

  acksPacket (val: number): boolean {
    if (val < this.lowestAcked || val > this.largestAcked) {
      return false
    }

    if (this.hasMissingRanges()) {
      // TODO: this could be implemented as a binary search
      for (let ackRange of this.ackRanges) {
        if (val >= ackRange.firstNum && val <= ackRange.lastNum) {
          return true
        }
      }
      return false
    }
    // if packet doesn't have missing ranges
    return (val >= this.lowestAcked && val <= this.largestAcked)
  }

  byteLen (): number {
    let hasMissingRanges = this.hasMissingRanges()
    let largestAckedNum = new PacketNumber(this.largestAcked)
    let flagBits = this.getMissingNumberDeltaFlagBits()
    let largestAckedLen = largestAckedNum.byteLen()
    let missingNumberDeltaLen = PacketNumber.flagToByteLen(flagBits)
    let frameLen = 1 + largestAckedLen + 2
    let numRanges = 0
    // Blocks
    if (!hasMissingRanges) frameLen += missingNumberDeltaLen
    else {
      numRanges = this.numWritableNackRanges()
      if (numRanges > 0xff) throw new Error('AckFrame: Too many ACK ranges')
      frameLen += missingNumberDeltaLen + 1
      frameLen += (missingNumberDeltaLen + 1) * (numRanges - 1)
    }
    // Timestamps
    return frameLen + 1
  }

  writeTo (bufv: BufferVisitor): BufferVisitor {
    let hasMissingRanges = this.hasMissingRanges()
    if (hasMissingRanges) this.type |= 0b100000

    let largestAckedNum = new PacketNumber(this.largestAcked)
    this.type |= largestAckedNum.flagBits() << 2
    let flagBits = this.getMissingNumberDeltaFlagBits()
    this.type |= flagBits

    let missingNumberDeltaLen = PacketNumber.flagToByteLen(flagBits)
    let numRanges = 0

    bufv.v.walk(1)
    bufv.writeUInt8(this.type, bufv.v.start)
    largestAckedNum.writeTo(bufv)

    if (!this.delayTime && this.packetReceivedTime) {
      let delayTime = process.hrtime(this.packetReceivedTime) // [seconds, nanoseconds]
      this.delayTime = delayTime[0] * 1000 * 1000 + Math.floor(delayTime[1] / 1000) // microsecond
    }
    bufv.v.walk(2)
    writeUFloat16(bufv, this.delayTime, bufv.v.start)

    let numRangesWritten = 0
    if (hasMissingRanges) {
      numRanges = this.numWritableNackRanges()
      if (numRanges > 0xff) throw new Error('AckFrame: Too many ACK ranges')
      bufv.v.walk(1)
      bufv.writeUInt8(numRanges - 1, bufv.v.start)
    }

    let firstAckBlockLength = 0
    if (!hasMissingRanges) {
      firstAckBlockLength = this.largestAcked - this.lowestAcked + 1
    } else {
      if (this.largestAcked !== this.ackRanges[0].lastNum) {
        throw new Error('largestAcked does not match ACK ranges')
      }
      if (this.lowestAcked !== this.ackRanges[this.ackRanges.length - 1].firstNum) {
        throw new Error('lowestAcked does not match ACK ranges')
      }
      firstAckBlockLength = this.largestAcked - this.ackRanges[0].firstNum + 1
      numRangesWritten++
    }

    bufv.v.walk(missingNumberDeltaLen)
    bufv.writeUIntLE(firstAckBlockLength, bufv.v.start, missingNumberDeltaLen)

    for (let i = 1, l = this.ackRanges.length; i < l; i++) {
      let length = this.ackRanges[i].lastNum - this.ackRanges[i].firstNum + 1
      let gap = this.ackRanges[i - 1].firstNum - this.ackRanges[i].lastNum - 1

      let num = Math.floor(gap / 0xff) + 1
      if (gap % 0xff === 0) {
        num--
      }

      if (num === 1) {
        bufv.v.walk(1)
        bufv.writeUInt8(gap, bufv.v.start)
        bufv.v.walk(missingNumberDeltaLen)
        bufv.writeUIntLE(length, bufv.v.start, missingNumberDeltaLen)
        numRangesWritten++
      } else {
        for (let j = 0; j < num; j++) {
          let lengthWritten = 0
          let gapWritten = 0

          if (j === num - 1) { // last block
            lengthWritten = length
            gapWritten = 1 + ((gap - 1) % 255)
          } else {
            lengthWritten = 0
            gapWritten = 0xff
          }

          bufv.v.walk(1)
          bufv.writeUInt8(gapWritten, bufv.v.start)
          bufv.v.walk(missingNumberDeltaLen)
          bufv.writeUIntLE(lengthWritten, bufv.v.start, missingNumberDeltaLen)
          numRangesWritten++
        }
      }
      // this is needed if not all AckRanges can be written to the ACK frame (if there are more than 0xFF)
      if (numRangesWritten >= numRanges) {
        break
      }
    }

    if (numRanges !== numRangesWritten) {
      throw new Error('BUG: Inconsistent number of ACK ranges written')
    }
    bufv.v.walk(1)
    bufv.writeUInt8(0, bufv.v.start) // no timestamps
    return bufv
  }

  static fromBuffer (bufv: BufferVisitor): AckFrame {
    bufv.v.walk(1)
    let type = bufv[bufv.v.start]
    if (!isACKType(type)) throw new QuicError('QUIC_INVALID_ACK_DATA')

    let frame = new AckFrame()
    let hasMissingRanges = type & 0b00100000
    let missingNumberDeltaLen = (2 * (type & 0b11)) || 1
    frame.largestAcked = PacketNumber.fromBuffer(bufv, PacketNumber.flagToByteLen((type & 0b1100) >> 2)).valueOf()

    bufv.v.walk(2)
    if (bufv.length < bufv.v.end) throw new QuicError('QUIC_INVALID_FRAME_DATA')
    frame.delayTime = readUFloat16(bufv, bufv.v.start)

    let numAckBlocks = 0
    if (hasMissingRanges) {
      bufv.v.walk(1)
      if (bufv.length < bufv.v.end) throw new QuicError('QUIC_INVALID_FRAME_DATA')
      numAckBlocks = bufv.readUInt8(bufv.v.start, true)
    }
    if (hasMissingRanges && numAckBlocks === 0) {
      throw new QuicError('QUIC_INVALID_FRAME_DATA')
    }
    bufv.v.walk(missingNumberDeltaLen)
    if (bufv.length < bufv.v.end) throw new QuicError('QUIC_INVALID_FRAME_DATA')
    let ackBlockLength = bufv.readUIntLE(bufv.v.start, missingNumberDeltaLen, true)
    let largestAcked = frame.largestAcked
    if ((largestAcked > 0 && ackBlockLength < 1) || ackBlockLength > largestAcked) {
      throw new QuicError('QUIC_INVALID_FRAME_DATA')
    }

    if (hasMissingRanges) {
      let ackRange = new AckRange(
        largestAcked - ackBlockLength + 1,
        largestAcked
      )
      frame.ackRanges.push(ackRange)

      let inLongBlock = false
      let lastRangeComplete = false
      for (let i = 0; i < numAckBlocks; i++) {
        bufv.v.walk(1)
        if (bufv.length < bufv.v.end) throw new QuicError('QUIC_INVALID_FRAME_DATA')
        let gap = bufv.readUInt8(bufv.v.start, true)

        bufv.v.walk(missingNumberDeltaLen)
        if (bufv.length < bufv.v.end) throw new QuicError('QUIC_INVALID_FRAME_DATA')
        ackBlockLength = bufv.readUIntLE(bufv.v.start, missingNumberDeltaLen, true)

        if (inLongBlock) {
          frame.ackRanges[frame.ackRanges.length - 1].firstNum -= gap + ackBlockLength
          frame.ackRanges[frame.ackRanges.length - 1].lastNum -= gap
        } else {
          lastRangeComplete = false
          ackRange = new AckRange(
            0,
            frame.ackRanges[frame.ackRanges.length - 1].firstNum - gap - 1
          )
          ackRange.firstNum = ackRange.lastNum - ackBlockLength + 1
          frame.ackRanges.push(ackRange)
        }

        if (ackBlockLength > 0) {
          lastRangeComplete = true
        }
        inLongBlock = (ackBlockLength === 0)
      }

      // if the last range was not complete, firstNum and lastNum make no sense
      // remove the range from frame.ackRanges
      if (!lastRangeComplete) {
        frame.ackRanges = frame.ackRanges.slice(0, -1)
      }
      frame.lowestAcked = frame.ackRanges[frame.ackRanges.length - 1].firstNum
    } else {
      if (frame.largestAcked === 0) {
        frame.lowestAcked = 0
      } else {
        frame.lowestAcked = largestAcked - ackBlockLength + 1
      }
    }

    if (!frame.validateAckRanges()) {
      throw new QuicError('QUIC_INVALID_FRAME_DATA')
    }

    bufv.v.walk(1)
    if (bufv.length < bufv.v.end) throw new QuicError('QUIC_INVALID_FRAME_DATA')
    let numTimestamp = bufv.readUInt8(bufv.v.start, true)
    if (numTimestamp > 0) { // TODO
      // Delta Largest acked
      bufv.v.walk(1)
      if (bufv.length < bufv.v.end) throw new QuicError('QUIC_INVALID_FRAME_DATA')
      // buf.readUInt8(v.start, true)
      // First Timestamp
      bufv.v.walk(4)
      if (bufv.length < bufv.v.end) throw new QuicError('QUIC_INVALID_FRAME_DATA')
      // buf.readUInt32LE(v.start, true)

      for (let i = 0; i < numTimestamp - 1; i++) {
        // Delta Largest acked
        bufv.v.walk(1)
        if (bufv.length < bufv.v.end) throw new QuicError('QUIC_INVALID_FRAME_DATA')
        // buf.readUInt8(v.start, true)
        // Time Since Previous Timestamp
        bufv.v.walk(2)
        if (bufv.length < bufv.v.end) throw new QuicError('QUIC_INVALID_FRAME_DATA')
        // buf.readUInt16LE(v.start, true)
      }
    }
    return frame
  }
}

/** StopWaitingFrame representing a QUIC STOP_WAITING frame. */
export class StopWaitingFrame extends Frame {
  // STOP_WAITING Frame
  //
  // --- src
  //      0        1        2        3         4       5       6
  // +--------+--------+--------+--------+--------+-------+-------+
  // |Type (8)|   Least unacked delta (8, 16, 32, or 48 bits)     |
  // |        |                       (variable length)           |
  // +--------+--------+--------+--------+--------+--------+------+
  // ---
  //
  // The fields in the STOP_WAITING frame are as follows:
  // * Frame Type: The Frame Type byte is an 8-bit value that must be set to 0x06 indicating that this is a STOP_WAITING frame.
  // * Least Unacked Delta: A variable length packet number delta with the same length as the packet header's packet number.  Subtract it from the header's packet number to determine the least unacked. The resulting least unacked is the smallest packet number of any packet for which the sender is still awaiting an ack. If the receiver is missing any packets smaller than this value, the receiver should consider those packets to be irrecoverably lost.
  //
  packetNumber: PacketNumber
  leastUnacked: PacketNumber
  constructor (packetNumber: PacketNumber, leastUnacked: PacketNumber) {
    super(0x06, 'STOP_WAITING')
    this.packetNumber = packetNumber // packetNumber > leastUnacked
    this.leastUnacked = leastUnacked
  }

  byteLen (): number {
    return 1 + this.packetNumber.byteLen()
  }

  writeTo (bufv: BufferVisitor): BufferVisitor {
    let len = this.packetNumber.byteLen()
    bufv.v.walk(1)
    bufv.writeUInt8(this.type, bufv.v.start)
    bufv.v.walk(len)
    bufv.writeUIntLE(this.packetNumber.valueOf() - this.leastUnacked.valueOf(), bufv.v.start, len)
    return bufv
  }

  static fromBuffer (bufv: BufferVisitor, packetNumber: PacketNumber): StopWaitingFrame {
    bufv.v.walk(1)
    let type = bufv[bufv.v.start]
    if (type !== 0x06) throw new QuicError('QUIC_INVALID_STOP_WAITING_DATA')

    let len = packetNumber.byteLen()
    bufv.v.walk(len)
    if (bufv.length < bufv.v.end) throw new QuicError('QUIC_INVALID_STOP_WAITING_DATA')
    let delta = bufv.readIntLE(bufv.v.start, len, false)
    return new StopWaitingFrame(packetNumber, new PacketNumber(packetNumber.valueOf() - delta))
  }
}

/** WindowUpdateFrame representing a QUIC WINDOW_UPDATE frame. */
export class WindowUpdateFrame extends Frame {
  // WINDOW_UPDATE Frame
  //
  // --- src
  //     0         1                 4        5                 12
  // +--------+--------+-- ... --+-------+--------+-- ... --+-------+
  // |Type(8) |    Stream ID (32 bits)   |  Byte offset (64 bits)   |
  // +--------+--------+-- ... --+-------+--------+-- ... --+-------+
  // ---
  // The fields in the WINDOW_UPDATE frame are as follows:
  // * Frame Type: The Frame Type byte is an 8-bit value that must be set to 0x04 indicating that this is a WINDOW_UPDATE frame.
  // * Stream ID: ID of the stream whose flow control windows is being updated, or 0 to specify the connection-level flow control window.
  // * Byte offset: A 64-bit unsigned integer indicating the absolute byte offset of data which can be sent on the given stream. In the case of connection level flow control, the cumulative number of bytes which can be sent on all currently open streams.
  //
  streamID: StreamID
  offset: Offset
  constructor (streamID: StreamID, offset: Offset) {
    super(0x04, 'WINDOW_UPDATE')
    this.streamID = streamID
    this.offset = offset
  }

  byteLen (): number {
    return 13
  }

  writeTo (bufv: BufferVisitor): BufferVisitor {
    bufv.v.walk(1)
    bufv.writeUInt8(this.type, bufv.v.start)
    this.streamID.writeTo(bufv, true)
    this.offset.writeTo(bufv, true)
    return bufv
  }

  static fromBuffer (bufv: BufferVisitor): WindowUpdateFrame {
    bufv.v.walk(1)
    let type = bufv[bufv.v.start]
    if (type !== 0x04) throw new QuicError('QUIC_INVALID_WINDOW_UPDATE_DATA')

    let streamID = StreamID.fromBuffer(bufv, 4)
    let offset = Offset.fromBuffer(bufv, 8)
    return new WindowUpdateFrame(streamID, offset)
  }
}

/** BlockedFrame representing a QUIC BLOCKED frame. */
export class BlockedFrame extends Frame {
  // BLOCKED Frame
  //
  // --- src
  //      0        1        2        3         4
  // +--------+--------+--------+--------+--------+
  // |Type(8) |          Stream ID (32 bits)      |
  // +--------+--------+--------+--------+--------+
  // ---
  //
  // The fields in the BLOCKED frame are as follows:
  // * Frame Type: The Frame Type byte is an 8-bit value that must be set to 0x05 indicating that this is a BLOCKED frame.
  // * Stream ID: A 32-bit unsigned number indicating the stream which is flow control blocked. A non-zero Stream ID field specifies the stream that is flow control blocked. When zero, the Stream ID field indicates that the connection is flow control blocked at the connection level.
  //
  streamID: StreamID
  constructor (streamID: StreamID) {
    super(0x05, 'BLOCKED')
    this.streamID = streamID
  }

  byteLen (): number {
    return 5
  }

  writeTo (bufv: BufferVisitor): BufferVisitor {
    bufv.v.walk(1)
    bufv.writeUInt8(this.type, bufv.v.start)
    this.streamID.writeTo(bufv, true)
    return bufv
  }

  static fromBuffer (bufv: BufferVisitor): BlockedFrame {
    bufv.v.walk(1)
    let type = bufv[bufv.v.start]
    if (type !== 0x05) throw new QuicError('QUIC_INVALID_BLOCKED_DATA')
    let streamID = StreamID.fromBuffer(bufv, 4)
    return new BlockedFrame(streamID)
  }
}

/** CongestionFeedbackFrame representing a QUIC CONGESTION_FEEDBACK frame. */
export class CongestionFeedbackFrame extends Frame {
  // CONGESTION_FEEDBACK Frame
  // The CONGESTION_FEEDBACK frame is an experimental frame currently not used.
  // It is intended to provide extra congestion feedback information outside the scope of
  // the standard ack frame. A CONGESTION_FEEDBACK frame must have the first three bits of
  // the Frame Type set to 001. The last 5 bits of the Frame Type field are reserved for future use.
  constructor () {
    super(0b00100000, 'CONGESTION_FEEDBACK')
  }

  byteLen (): number {
    return 1
  }

  writeTo (bufv: BufferVisitor): BufferVisitor {
    bufv.v.walk(1)
    bufv.writeUInt8(this.type, bufv.v.start)
    return bufv
  }

  static fromBuffer (bufv: BufferVisitor): CongestionFeedbackFrame {
    bufv.v.walk(1)
    let type = bufv[bufv.v.start]
    if (!isCongestionType(type)) throw new QuicError('QUIC_INVALID_FRAME_DATA')
    return new CongestionFeedbackFrame()
  }
}

/** PaddingFrame representing a QUIC PADDING frame. */
export class PaddingFrame extends Frame {
  // PADDING Frame
  // The PADDING frame pads a packet with 0x00 bytes. When this frame is encountered,
  // the rest of the packet is expected to be padding bytes. The frame contains 0x00 bytes
  // and extends to the end of the QUIC packet. A PADDING frame only has a Frame Type field,
  // and must have the 8-bit Frame Type field set to 0x00.
  constructor () {
    super(0x00, 'PADDING')
  }

  byteLen (): number {
    return 1
  }

  writeTo (bufv: BufferVisitor): BufferVisitor {
    bufv.v.walk(1)
    bufv.writeUInt8(0, bufv.v.start)
    return bufv
  }

  static fromBuffer (bufv: BufferVisitor): PaddingFrame {
    bufv.v.walk(1)
    let type = bufv[bufv.v.start]
    if (type) throw new QuicError('QUIC_INVALID_FRAME_DATA')
    return new PaddingFrame()
  }
}

/** RstStreamFrame representing a QUIC RST_STREAM frame. */
export class RstStreamFrame extends Frame {
  // RST_STREAM Frame
  //
  // --- src
  //      0        1            4      5              12     8             16
  // +-------+--------+-- ... ----+--------+-- ... ------+-------+-- ... ------+
  // |Type(8)| StreamID (32 bits) | Byte offset (64 bits)| Error code (32 bits)|
  // +-------+--------+-- ... ----+--------+-- ... ------+-------+-- ... ------+
  // ---
  //
  // The fields in a RST_STREAM frame are as follows:
  // * Frame type: The Frame Type is an 8-bit value that must be set to 0x01 specifying that this is a RST_STREAM frame.
  // * Stream ID: The 32-bit Stream ID of the stream being terminated.
  // * Byte offset: A 64-bit unsigned integer indicating the absolute byte offset of the end of data for this stream.
  // * Error code: A 32-bit QuicErrorCode which indicates why the stream is being closed. QuicErrorCodes are listed later in this document.
  //
  streamID: StreamID
  offset: Offset
  error: QuicStreamError
  constructor (streamID: StreamID, offset: Offset, error: QuicStreamError) {
    super(0x01, 'RST_STREAM')
    this.streamID = streamID
    this.offset = offset
    this.error = error
  }

  byteLen (): number {
    return 17
  }

  writeTo (bufv: BufferVisitor): BufferVisitor {
    bufv.v.walk(1)
    bufv.writeUInt8(this.type, bufv.v.start)
    this.streamID.writeTo(bufv, true)
    this.offset.writeTo(bufv, true)
    this.error.writeTo(bufv)
    return bufv
  }

  static fromBuffer (bufv: BufferVisitor): RstStreamFrame {
    bufv.v.walk(1)
    let type = bufv[bufv.v.start]
    if (type !== 0x01 || bufv.length < (bufv.v.end + 16)) throw new QuicError('QUIC_INVALID_RST_STREAM_DATA')
    let streamID = StreamID.fromBuffer(bufv, 4)
    let offset = Offset.fromBuffer(bufv, 8)
    let error = QuicError.fromBuffer(bufv)
    return new RstStreamFrame(streamID, offset, error)
  }
}

/** PingFrame representing a QUIC PING frame. */
export class PingFrame extends Frame {
  // PING frame
  // The PING frame can be used by an endpoint to verify that
  // a peer is still alive. The PING frame contains no payload.
  // The receiver of a PING frame simply needs to ACK the packet containing this frame.
  // The PING frame should be used to keep a connection alive when a stream is open.
  // The default is to do this after 15 seconds of quiescence,
  // which is much shorter than most NATs time out. A PING frame only
  // has a Frame Type field, and must have the 8-bit Frame Type field set to 0x07.
  constructor () {
    super(0x07, 'PING')
  }

  byteLen (): number {
    return 1
  }

  writeTo (bufv: BufferVisitor): BufferVisitor {
    bufv.v.walk(1)
    bufv.writeUInt8(this.type, bufv.v.start)
    return bufv
  }

  static fromBuffer (bufv: BufferVisitor): PingFrame {
    bufv.v.walk(1)
    let type = bufv[bufv.v.start]
    if (type !== 0x07) throw new QuicError('QUIC_INVALID_FRAME_DATA')
    return new PingFrame()
  }
}

/** ConnectionCloseFrame representing a QUIC CONNECTION_CLOSE frame. */
export class ConnectionCloseFrame extends Frame {
  // CONNECTION_CLOSE frame
  //
  // --- src
  //      0        1             4        5        6       7
  // +--------+--------+-- ... -----+--------+--------+--------+----- ...
  // |Type(8) | Error code (32 bits)| Reason phrase   |  Reason phrase
  // |        |                     | length (16 bits)|(variable length)
  // +--------+--------+-- ... -----+--------+--------+--------+----- ...
  // ---
  //
  // The fields of a CONNECTION_CLOSE frame are as follows:
  // * Frame Type: An 8-bit value that must be set to 0x02 specifying that this is a CONNECTION_CLOSE frame.
  // * Error Code: A 32-bit field containing the QuicErrorCode which indicates the reason for closing this connection.
  // * Reason Phrase Length: A 16-bit unsigned number specifying the length of the reason phrase. This may be zero if the sender chooses to not give details beyond the QuicErrorCode.
  // * Reason Phrase: An optional human-readable explanation for why the connection was closed.
  //
  error: QuicError
  constructor (error: QuicError) {
    super(0x02, 'CONNECTION_CLOSE')
    this.error = error
  }

  byteLen (): number {
    let reasonPhrase = this.error.message
    let reasonPhraseLen = reasonPhrase ? Buffer.byteLength(reasonPhrase) : 0
    return 7 + reasonPhraseLen
  }

  writeTo (bufv: BufferVisitor): BufferVisitor {
    let reasonPhrase = this.error.message
    let reasonPhraseLen = reasonPhrase ? Buffer.byteLength(reasonPhrase) : 0
    bufv.v.walk(1)
    bufv.writeUInt8(this.type, bufv.v.start)
    this.error.writeTo(bufv)
    bufv.v.walk(2)
    bufv.writeUInt16LE(reasonPhraseLen, bufv.v.start, true)
    if (reasonPhrase) {
      bufv.v.walk(reasonPhraseLen)
      bufv.write(reasonPhrase, bufv.v.start, reasonPhraseLen)
    }
    return bufv
  }

  static fromBuffer (bufv: BufferVisitor): ConnectionCloseFrame {
    bufv.v.walk(1)
    let type = bufv[bufv.v.start]
    if (type !== 0x02 || bufv.length < (bufv.v.end + 6)) throw new QuicError('QUIC_INVALID_CONNECTION_CLOSE_DATA')
    let error = QuicError.fromBuffer(bufv)
    bufv.v.walk(2)
    let reasonPhraseLen = bufv.readUInt16LE(bufv.v.start, true)
    if (reasonPhraseLen) {
      bufv.v.walk(reasonPhraseLen)
      if (bufv.length < bufv.v.end) throw new QuicError('QUIC_INVALID_CONNECTION_CLOSE_DATA')
      error.message = bufv.toString('utf8', bufv.v.start, bufv.v.end)
    }
    return new ConnectionCloseFrame(error)
  }
}

/** GoAwayFrame representing a QUIC GOAWAY frame. */
export class GoAwayFrame extends Frame {
  // GOAWAY Frame
  //
  // --- src
  //      0        1             4      5       6       7      8
  // +--------+--------+-- ... -----+-------+-------+-------+------+
  // |Type(8) | Error code (32 bits)| Last Good Stream ID (32 bits)| ->
  // +--------+--------+-- ... -----+-------+-------+-------+------+
  //
  //       9        10       11
  // +--------+--------+--------+----- ...
  // | Reason phrase   |  Reason phrase
  // | length (16 bits)|(variable length)
  // +--------+--------+--------+----- ...
  // ---
  //
  // The fields of a GOAWAY frame are as follows:
  // * Frame type: An 8-bit value that must be set to 0x03 specifying that this is a GOAWAY frame.
  // * Error Code: A 32-bit field containing the QuicErrorCode which indicates the reason for closing this connection.
  // * Last Good Stream ID: The last Stream ID which was accepted by the sender of the GOAWAY message. If no streams were replied to, this value must be set to 0.
  // * Reason Phrase Length: A 16-bit unsigned number specifying the length of the reason phrase. This may be zero if the sender chooses to not give details beyond the error code.
  // * Reason Phrase: An optional human-readable explanation for why the connection was closed.
  //
  streamID: StreamID
  error: QuicError
  constructor (lastGoodStreamID: StreamID, error: QuicError) {
    super(0x03, 'GOAWAY')
    this.streamID = lastGoodStreamID
    this.error = error
  }

  byteLen (): number {
    let reasonPhrase = this.error.message
    let reasonPhraseLen = reasonPhrase ? Buffer.byteLength(reasonPhrase) : 0
    return 11 + reasonPhraseLen
  }

  writeTo (bufv: BufferVisitor): BufferVisitor {
    let reasonPhrase = this.error.message
    let reasonPhraseLen = reasonPhrase ? Buffer.byteLength(reasonPhrase) : 0

    bufv.v.walk(1)
    bufv.writeUInt8(this.type, bufv.v.start)
    this.error.writeTo(bufv)
    this.streamID.writeTo(bufv, true)
    bufv.v.walk(2)
    bufv.writeUInt16LE(reasonPhraseLen, bufv.v.start, true)
    if (reasonPhrase) {
      bufv.v.walk(reasonPhraseLen)
      bufv.write(reasonPhrase, bufv.v.start, reasonPhraseLen)
    }
    return bufv
  }

  static fromBuffer (bufv: BufferVisitor): GoAwayFrame {
    bufv.v.walk(1)
    let type = bufv[bufv.v.start]
    if (type !== 0x03) throw new QuicError('QUIC_INVALID_GOAWAY_DATA')

    let error = QuicError.fromBuffer(bufv)
    let streamID = StreamID.fromBuffer(bufv, 4)
    bufv.v.walk(2)
    if (bufv.length < bufv.v.end) throw new QuicError('QUIC_INVALID_GOAWAY_DATA')
    let reasonPhraseLen = bufv.readUInt16LE(bufv.v.start, true)
    if (reasonPhraseLen) {
      bufv.v.walk(reasonPhraseLen)
      if (bufv.length < bufv.v.end) throw new QuicError('QUIC_INVALID_GOAWAY_DATA')
      error.message = bufv.toString('utf8', bufv.v.start, bufv.v.end)
    }
    return new GoAwayFrame(streamID, error)
  }
}
