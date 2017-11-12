'use strict'

// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const { suite, it } = require('tman')
const { ok, strictEqual, deepEqual, throws } = require('assert')
const { Visitor } = require('../lib/common')
const { StreamID, Offset, PacketNumber } = require('../lib/protocol')
const { StreamFrame, AckFrame, AckRange, PaddingFrame, RstStreamFrame, ConnectionCloseFrame, GoAwayFrame, WindowUpdateFrame, BlockedFrame,
  StopWaitingFrame, PingFrame, CongestionFeedbackFrame } = require('../lib/frame')
const { QuicError } = require('../lib/error')
const { bufferFromBytes } = require('./common')

suite('QUIC Frame', function () {
  suite('STREAM Frame', function () {
    it('new StreamFrame', function () {
      let streamID = StreamID.fromValue(1)
      let offset = Offset.fromValue(0)
      let data = bufferFromBytes(['abcdefg'])
      let streamFrame = new StreamFrame(streamID, offset, data, false)

      strictEqual(streamFrame.isFIN, false)
      let buf = streamFrame.toBuffer()
      ok(buf.equals(bufferFromBytes([
        0b10100000,
        0x1,
        0x7, 0x0,
        'abcdefg'
      ])))
      ok(buf.equals(StreamFrame.fromBuffer(Visitor.wrap(buf)).toBuffer()))

      streamID = streamID.nextID()
      offset = offset.nextOffset(data.length)
      data = bufferFromBytes(['higklmn'])
      streamFrame = new StreamFrame(streamID, offset, data, false)

      strictEqual(streamFrame.isFIN, false)
      buf = streamFrame.toBuffer()
      ok(buf.equals(bufferFromBytes([
        0b10100100,
        0x3,
        0x7, 0x0,
        0x7, 0x0,
        'higklmn'
      ])))
      ok(buf.equals(StreamFrame.fromBuffer(Visitor.wrap(buf)).toBuffer()))

      streamID = streamID.nextID()
      offset = offset.nextOffset(data.length)
      data = bufferFromBytes(['opqrst'])
      streamFrame = new StreamFrame(streamID, offset, data, false)

      strictEqual(streamFrame.isFIN, false)
      buf = streamFrame.toBuffer()
      ok(buf.equals(bufferFromBytes([
        0b10100100,
        0x5,
        0xe, 0x0,
        0x6, 0x0,
        'opqrst'
      ])))
      ok(buf.equals(StreamFrame.fromBuffer(Visitor.wrap(buf)).toBuffer()))

      streamID = streamID.nextID()
      offset = offset.nextOffset(data.length)
      data = bufferFromBytes(['uvwxyz'])
      streamFrame = new StreamFrame(streamID, offset, data, true)

      strictEqual(streamFrame.isFIN, true)
      buf = streamFrame.toBuffer()
      ok(buf.equals(bufferFromBytes([
        0b11100100,
        0x7,
        0x14, 0x0,
        0x6, 0x0,
        'uvwxyz'
      ])))
      ok(buf.equals(StreamFrame.fromBuffer(Visitor.wrap(buf)).toBuffer()))
    })

    it('when invalid StreamFrame type', function () {
      let streamID = StreamID.fromValue(1)
      let offset = Offset.fromValue(0)
      let data = bufferFromBytes(['abcd'])
      let streamFrame = new StreamFrame(streamID, offset, data, false)
      let buf = streamFrame.toBuffer()

      throws(() => StreamFrame.fromBuffer(Visitor.wrap(buf.slice(0, 1))), /INVALID_STREAM_DATA/)
      throws(() => StreamFrame.fromBuffer(Visitor.wrap(buf.slice(0, 2))), /INVALID_STREAM_DATA/)
      throws(() => StreamFrame.fromBuffer(Visitor.wrap(buf.slice(0, 3))), /INVALID_STREAM_DATA/)
      throws(() => StreamFrame.fromBuffer(Visitor.wrap(buf.slice(0, 4))), /INVALID_STREAM_DATA/)
      throws(() => StreamFrame.fromBuffer(Visitor.wrap(buf.slice(0, 5))), /INVALID_STREAM_DATA/)
      throws(() => StreamFrame.fromBuffer(Visitor.wrap(buf.slice(0, 6))), /INVALID_STREAM_DATA/)
      throws(() => StreamFrame.fromBuffer(Visitor.wrap(buf.slice(0, 7))), /INVALID_STREAM_DATA/)
      ok(buf.equals(StreamFrame.fromBuffer(Visitor.wrap(buf.slice(0, streamFrame.byteLen))).toBuffer()))
    })
  })

  suite('ACK Frame', function () {
    suite('parsing', function () {
      it('a sample ACK frame', function () {
        let buf = bufferFromBytes([0b01000000, 0x1c, 0x8e, 0x0, 0x1c, 0x1, 0x1, 0x6b, 0x26, 0x3, 0x0])
        let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
        ok(ackFrame.largestAcked === 0x1c)
        ok(ackFrame.lowestAcked === 0x1)
        ok(ackFrame.delayTime === 142)
        ok(ackFrame.hasMissingRanges() === false)

        // ignore Timestamps
        deepEqual(ackFrame.toBuffer(), bufferFromBytes([0b01000000, 0x1c, 0x8e, 0x0, 0x1c, 0x0]))
      })

      it('a frame without a timestamp', function () {
        let buf = bufferFromBytes([0x40, 0x3, 0x50, 0x15, 0x3, 0x0])
        let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
        ok(ackFrame.largestAcked === 0x3)
        ok(ackFrame.lowestAcked === 0x1)
        ok(ackFrame.delayTime === 6816)
        ok(ackFrame.hasMissingRanges() === false)
      })

      it('a frame where the largest acked is 0', function () {
        let buf = bufferFromBytes([0x40, 0x0, 0xff, 0xff, 0x0, 0x0])
        let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
        ok(ackFrame.largestAcked === 0x0)
        ok(ackFrame.lowestAcked === 0x0)
        ok(ackFrame.hasMissingRanges() === false)
      })

      it('a frame with a 48 bit packet number', function () {
        let buf = bufferFromBytes([0x4c, 0x37, 0x13, 0xad, 0xfb, 0xca, 0xde, 0x0, 0x0, 0x5, 0x1, 0, 0, 0, 0, 0])
        let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
        ok(ackFrame.largestAcked === 0xdecafbad1337)
        ok(ackFrame.lowestAcked === 0xdecafbad1337 - 5 + 1)
        ok(ackFrame.hasMissingRanges() === false)
      })

      it('a frame with 1 ACKed packet', function () {
        let buf = bufferFromBytes([0x40, 0x10, 0x8e, 0x0, 0x1, 0x0])
        let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
        ok(ackFrame.largestAcked === 0x10)
        ok(ackFrame.lowestAcked === 0x10)
        ok(ackFrame.hasMissingRanges() === false)
      })

      it('a frame, when packet 1 was lost', function () {
        let buf = bufferFromBytes([0x40, 0x9, 0x92, 0x7, 0x8, 0x3, 0x2, 0x69, 0xa3, 0x0, 0x0, 0x1, 0xc9, 0x2, 0x0, 0x46, 0x10])
        let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
        ok(ackFrame.largestAcked === 9)
        ok(ackFrame.lowestAcked === 2)
        ok(ackFrame.hasMissingRanges() === false)
      })

      it('a frame with multiple timestamps', function () {
        let buf = bufferFromBytes([0x40, 0x10, 0x0, 0x0, 0x10, 0x4, 0x1, 0x6b, 0x26, 0x4, 0x0, 0x3, 0, 0, 0x2, 0, 0, 0x1, 0, 0])
        let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
        ok(ackFrame.largestAcked === 0x10)
        ok(ackFrame.lowestAcked === 1)
        ok(ackFrame.hasMissingRanges() === false)
      })

      it('errors when the ACK range is too large', function () {
        // LargestAcked: 0x1c
        // Length: 0x1d => LowestAcked would be -1
        throws(() => {
          let buf = bufferFromBytes([0x40, 0x1c, 0x8e, 0x0, 0x1d, 0x1, 0x1, 0x6b, 0x26, 0x3, 0x0])
          AckFrame.fromBuffer(Visitor.wrap(buf))
        })
      })

      it('errors when the first ACK range is empty', function () {
        throws(() => {
          let buf = bufferFromBytes([0x40, 0x9, 0x8e, 0x0, 0x0, 0x1, 0])
          AckFrame.fromBuffer(Visitor.wrap(buf))
        })
      })
    })

    suite('ACK blocks', function () {
      it('a frame with one ACK block', function () {
        let buf = bufferFromBytes([0x60, 0x18, 0x94, 0x1, 0x1, 0x3, 0x2, 0x10, 0x2, 0x1, 0x5c, 0xd5, 0x0, 0x0, 0x0, 0x95, 0x0])
        let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
        ok(ackFrame.largestAcked === 0x18)
        ok(ackFrame.lowestAcked === 0x4)
        strictEqual(ackFrame.hasMissingRanges(), true)
        strictEqual(ackFrame.ackRanges.length, 2)
        deepEqual(ackFrame.ackRanges[0], new AckRange(22, 24))
        deepEqual(ackFrame.ackRanges[1], new AckRange(4, 19))
      })

      it('rejects a frame that says it has ACK blocks in the typeByte, but doesn\'t have any', function () {
        let buf = bufferFromBytes([0x63, 0x4, 0xff, 0xff, 0, 2, 0, 0, 0, 0, 0, 0])
        throws(() => AckFrame.fromBuffer(Visitor.wrap(buf)))
      })

      it('rejects a frame with invalid ACK ranges', function () {
        // like the test before, but increased the last ACK range, such that the FirstPacketNumber would be negative
        let buf = bufferFromBytes([0x60, 0x18, 0x94, 0x1, 0x1, 0x3, 0x2, 0x15, 0x2, 0x1, 0x5c, 0xd5, 0x0, 0x0, 0x0, 0x95, 0x0])
        throws(() => AckFrame.fromBuffer(Visitor.wrap(buf)))
      })

      it('a frame with multiple single packets missing', function () {
        let buf = bufferFromBytes([0x60, 0x27, 0xda, 0x0, 0x6, 0x9, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x13, 0x2, 0x1, 0x71, 0x12, 0x3, 0x0, 0x0, 0x47, 0x2])
        let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
        ok(ackFrame.largestAcked === 0x27)
        ok(ackFrame.lowestAcked === 0x1)
        strictEqual(ackFrame.hasMissingRanges(), true)
        strictEqual(ackFrame.ackRanges.length, 7)
        deepEqual(ackFrame.ackRanges[0], new AckRange(31, 39))
        deepEqual(ackFrame.ackRanges[1], new AckRange(29, 29))
        deepEqual(ackFrame.ackRanges[2], new AckRange(27, 27))
        deepEqual(ackFrame.ackRanges[3], new AckRange(25, 25))
        deepEqual(ackFrame.ackRanges[4], new AckRange(23, 23))
        deepEqual(ackFrame.ackRanges[5], new AckRange(21, 21))
        deepEqual(ackFrame.ackRanges[6], new AckRange(1, 19))
      })

      it('a frame with packet 1 and one more packet lost', function () {
        let buf = bufferFromBytes([0x60, 0xc, 0x92, 0x0, 0x1, 0x1, 0x1, 0x9, 0x2, 0x2, 0x53, 0x43, 0x1, 0x0, 0x0, 0xa7, 0x0])
        let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
        ok(ackFrame.largestAcked === 12)
        ok(ackFrame.lowestAcked === 2)
        strictEqual(ackFrame.hasMissingRanges(), true)
        strictEqual(ackFrame.ackRanges.length, 2)
        deepEqual(ackFrame.ackRanges[0], new AckRange(12, 12))
        deepEqual(ackFrame.ackRanges[1], new AckRange(2, 10))
      })

      it('a frame with multiple longer ACK blocks', function () {
        let buf = bufferFromBytes([0x60, 0x52, 0xd1, 0x0, 0x3, 0x17, 0xa, 0x10, 0x4, 0x8, 0x2, 0x12, 0x2, 0x1, 0x6c, 0xc8, 0x2, 0x0, 0x0, 0x7e, 0x1])
        let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
        ok(ackFrame.largestAcked === 0x52)
        ok(ackFrame.lowestAcked === 2)
        strictEqual(ackFrame.hasMissingRanges(), true)
        strictEqual(ackFrame.ackRanges.length, 4)
        deepEqual(ackFrame.ackRanges[0], new AckRange(60, 0x52))
        deepEqual(ackFrame.ackRanges[1], new AckRange(34, 49))
        deepEqual(ackFrame.ackRanges[2], new AckRange(22, 29))
        deepEqual(ackFrame.ackRanges[3], new AckRange(2, 19))
      })

      suite('more than 256 lost packets in a row', function () {
        // 255 missing packets fit into a single ACK block
        it('a frame with a range of 255 missing packets', function () {
          let buf = bufferFromBytes([0x64, 0x15, 0x1, 0xce, 0x1, 0x1, 0x3, 0xff, 0x13, 0x1, 0x0, 0xb6, 0xc5, 0x0, 0x0])
          let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
          ok(ackFrame.largestAcked === 0x115)
          ok(ackFrame.lowestAcked === 1)
          strictEqual(ackFrame.hasMissingRanges(), true)
          strictEqual(ackFrame.ackRanges.length, 2)
          deepEqual(ackFrame.ackRanges[0], new AckRange(20 + 255, 0x115))
          deepEqual(ackFrame.ackRanges[1], new AckRange(1, 19))
        })

        // 256 missing packets fit into two ACK blocks
        it('a frame with a range of 256 missing packets', function () {
          let buf = bufferFromBytes([0x64, 0x14, 0x1, 0x96, 0x0, 0x2, 0x1, 0xff, 0x0, 0x1, 0x13, 0x1, 0x0, 0x92, 0xc0, 0x0, 0x0])
          let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
          ok(ackFrame.largestAcked === 0x114)
          ok(ackFrame.lowestAcked === 1)
          strictEqual(ackFrame.hasMissingRanges(), true)
          strictEqual(ackFrame.ackRanges.length, 2)
          deepEqual(ackFrame.ackRanges[0], new AckRange(20 + 256, 0x114))
          deepEqual(ackFrame.ackRanges[1], new AckRange(1, 19))
        })

        it('a frame with an incomplete range at the end', function () {
          // this is a modified ACK frame that has 5 instead of originally 6 written ranges
          // each gap is 300 packets and thus takes 2 ranges
          // the last range is incomplete, and should be completely ignored
          let buf = bufferFromBytes([0x64, 0x9b, 0x3, 0xc9, 0x0, 0x5 /* instead of 0x6 */, 0x1, 0xff, 0x0, 0x2d, 0x1, 0xff, 0x0, 0x2d, 0x1, 0xff, 0x0 /* 0x2d, 0x14, */, 0x1, 0x0, 0xf6, 0xbd, 0x0, 0x0])
          let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
          ok(ackFrame.largestAcked === 0x39b)
          ok(ackFrame.lowestAcked === 0x141)
          strictEqual(ackFrame.hasMissingRanges(), true)
          strictEqual(ackFrame.ackRanges.length, 3)
          deepEqual(ackFrame.ackRanges[0], new AckRange(20 + 3 * 301, 20 + 3 * 301))
          deepEqual(ackFrame.ackRanges[1], new AckRange(20 + 2 * 301, 20 + 2 * 301))
          deepEqual(ackFrame.ackRanges[2], new AckRange(20 + 1 * 301, 20 + 1 * 301))
        })

        it('a frame with one long range, spanning 2 blocks, of missing packets', function () { // 280 missing packets
          let buf = bufferFromBytes([0x64, 0x44, 0x1, 0xa7, 0x0, 0x2, 0x19, 0xff, 0x0, 0x19, 0x13, 0x2, 0x1, 0xb, 0x59, 0x2, 0x0, 0x0, 0xb6, 0x0])
          let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
          ok(ackFrame.largestAcked === 0x144)
          ok(ackFrame.lowestAcked === 1)
          strictEqual(ackFrame.hasMissingRanges(), true)
          strictEqual(ackFrame.ackRanges.length, 2)
          deepEqual(ackFrame.ackRanges[0], new AckRange(300, 0x144))
          deepEqual(ackFrame.ackRanges[1], new AckRange(1, 19))
        })

        it('a frame with one long range, spanning multiple blocks, of missing packets', function () { // 2345 missing packets
          let buf = bufferFromBytes([0x64, 0x5b, 0x9, 0x66, 0x1, 0xa, 0x1f, 0xff, 0x0, 0xff, 0x0, 0xff, 0x0, 0xff, 0x0, 0xff, 0x0, 0xff, 0x0, 0xff, 0x0, 0xff, 0x0, 0xff, 0x0, 0x32, 0x13, 0x4, 0x3, 0xb4, 0xda, 0x1, 0x0, 0x2, 0xe0, 0x0, 0x1, 0x9a, 0x0, 0x0, 0x81, 0x0])
          let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
          ok(ackFrame.largestAcked === 0x95b)
          ok(ackFrame.lowestAcked === 1)
          strictEqual(ackFrame.hasMissingRanges(), true)
          strictEqual(ackFrame.ackRanges.length, 2)
          deepEqual(ackFrame.ackRanges[0], new AckRange(2365, 0x95b))
          deepEqual(ackFrame.ackRanges[1], new AckRange(1, 19))
        })

        it('a frame with multiple long ranges of missing packets', function () {
          let buf = bufferFromBytes([0x65, 0x66, 0x9, 0x23, 0x1, 0x7, 0x7, 0x0, 0xff, 0x0, 0x0, 0xf5, 0x8a, 0x2, 0xc8, 0xe6, 0x0, 0xff, 0x0, 0x0, 0xff, 0x0, 0x0, 0xff, 0x0, 0x0, 0x23, 0x13, 0x0, 0x2, 0x1, 0x13, 0xae, 0xb, 0x0, 0x0, 0x80, 0x5])
          let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
          ok(ackFrame.largestAcked === 0x966)
          ok(ackFrame.lowestAcked === 1)
          strictEqual(ackFrame.hasMissingRanges(), true)
          strictEqual(ackFrame.ackRanges.length, 4)
          deepEqual(ackFrame.ackRanges[0], new AckRange(2400, 0x966))
          deepEqual(ackFrame.ackRanges[1], new AckRange(1250, 1899))
          deepEqual(ackFrame.ackRanges[2], new AckRange(820, 1049))
          deepEqual(ackFrame.ackRanges[3], new AckRange(1, 19))
        })

        it('a frame with short ranges and one long range', function () {
          let buf = bufferFromBytes([0x64, 0x8f, 0x3, 0x65, 0x1, 0x5, 0x3d, 0x1, 0x32, 0xff, 0x0, 0xff, 0x0, 0xf0, 0x1c, 0x2, 0x13, 0x3, 0x2, 0x23, 0xaf, 0x2, 0x0, 0x1, 0x3, 0x1, 0x0, 0x8e, 0x0])
          let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
          ok(ackFrame.largestAcked === 0x38f)
          ok(ackFrame.lowestAcked === 1)
          strictEqual(ackFrame.hasMissingRanges(), true)
          strictEqual(ackFrame.ackRanges.length, 4)
          deepEqual(ackFrame.ackRanges[0], new AckRange(851, 0x38f))
          deepEqual(ackFrame.ackRanges[1], new AckRange(800, 849))
          deepEqual(ackFrame.ackRanges[2], new AckRange(22, 49))
          deepEqual(ackFrame.ackRanges[3], new AckRange(1, 19))
        })
      })
    })

    it('errors on EOFs', function () {
      let buf = bufferFromBytes([0x65, 0x66, 0x9, 0x23, 0x1, 0x7, 0x7, 0x0, 0xff, 0x0, 0x0, 0xf5, 0x8a, 0x2, 0xc8, 0xe6, 0x0, 0xff, 0x0, 0x0, 0xff, 0x0, 0x0, 0xff, 0x0, 0x0, 0x23, 0x13, 0x0, 0x2, 0x1, 0x13, 0xae, 0xb, 0x0, 0x0, 0x80, 0x5])
      AckFrame.fromBuffer(Visitor.wrap(buf))
      for (let i = 0; i < buf.length; i++) {
        throws(() => AckFrame.fromBuffer(Visitor.wrap(buf.slice(0, i))))
      }
    })

    suite('when toBuffer', function () {
      suite('self-consistency', function () {
        it('a simple ACK frame', function () {
          let frame = new AckFrame()
          frame.largestAcked = 1
          frame.lowestAcked = 1
          let buf = frame.toBuffer()
          let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
          ok(ackFrame.largestAcked === 1)
          ok(ackFrame.lowestAcked === 1)
          strictEqual(ackFrame.hasMissingRanges(), false)
        })

        it('the correct block length in a simple ACK frame', function () {
          let frame = new AckFrame()
          frame.largestAcked = 20
          frame.lowestAcked = 10
          let buf = frame.toBuffer()
          let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
          ok(ackFrame.largestAcked === 20)
          ok(ackFrame.lowestAcked === 10)
          strictEqual(ackFrame.hasMissingRanges(), false)
        })

        it('a simple ACK frame with a high packet number', function () {
          let frame = new AckFrame()
          frame.largestAcked = 0xDEADBEEFCAFE
          frame.lowestAcked = 0xDEADBEEFCAFE
          let buf = frame.toBuffer()
          let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
          ok(ackFrame.largestAcked === 0xDEADBEEFCAFE)
          ok(ackFrame.lowestAcked === 0xDEADBEEFCAFE)
          strictEqual(ackFrame.hasMissingRanges(), false)
        })

        it('an ACK frame with one packet missing', function () {
          let frame = new AckFrame()
          frame.largestAcked = 40
          frame.lowestAcked = 1
          frame.ackRanges.push(new AckRange(25, 40), new AckRange(1, 23))
          let buf = frame.toBuffer()
          let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
          ok(ackFrame.largestAcked === 40)
          ok(ackFrame.lowestAcked === 1)
          strictEqual(ackFrame.hasMissingRanges(), true)
          strictEqual(ackFrame.ackRanges.length, 2)
          deepEqual(ackFrame.ackRanges[0], new AckRange(25, 40))
          deepEqual(ackFrame.ackRanges[1], new AckRange(1, 23))
        })

        it('an ACK frame with multiple missing packets', function () {
          let frame = new AckFrame()
          frame.largestAcked = 25
          frame.lowestAcked = 1
          frame.ackRanges.push(
            new AckRange(22, 25),
            new AckRange(15, 18),
            new AckRange(13, 13),
            new AckRange(1, 10)
          )
          let buf = frame.toBuffer()
          let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
          ok(ackFrame.largestAcked === 25)
          ok(ackFrame.lowestAcked === 1)
          strictEqual(ackFrame.hasMissingRanges(), true)
          strictEqual(ackFrame.ackRanges.length, 4)
          deepEqual(ackFrame.ackRanges[0], new AckRange(22, 25))
          deepEqual(ackFrame.ackRanges[1], new AckRange(15, 18))
          deepEqual(ackFrame.ackRanges[2], new AckRange(13, 13))
          deepEqual(ackFrame.ackRanges[3], new AckRange(1, 10))
        })

        it('rejects a frame with incorrect LargestObserved value', function () {
          let frame = new AckFrame()
          frame.largestAcked = 26
          frame.lowestAcked = 1
          frame.ackRanges.push(
            new AckRange(12, 25),
            new AckRange(1, 10)
          )
          throws(() => frame.toBuffer())
        })

        it('rejects a frame with incorrect LargestObserved value 2', function () {
          let frame = new AckFrame()
          frame.largestAcked = 25
          frame.lowestAcked = 2
          frame.ackRanges.push(
            new AckRange(12, 25),
            new AckRange(1, 10)
          )
          throws(() => frame.toBuffer())
        })

        suite('longer gaps between ACK blocks', function () {
          it('only one block for 254 lost packets', function () {
            let frame = new AckFrame()
            frame.largestAcked = 300
            frame.lowestAcked = 1
            frame.ackRanges.push(
              new AckRange(20 + 254, 300),
              new AckRange(1, 19)
            )
            strictEqual(frame.numWritableNackRanges(), 2)

            let buf = frame.toBuffer()
            let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
            ok(ackFrame.largestAcked === 300)
            ok(ackFrame.lowestAcked === 1)
            strictEqual(ackFrame.hasMissingRanges(), true)
            strictEqual(ackFrame.ackRanges.length, 2)
            deepEqual(ackFrame.ackRanges[0], new AckRange(20 + 254, 300))
            deepEqual(ackFrame.ackRanges[1], new AckRange(1, 19))
          })

          it('only one block for 255 lost packets', function () {
            let frame = new AckFrame()
            frame.largestAcked = 300
            frame.lowestAcked = 1
            frame.ackRanges.push(
              new AckRange(20 + 255, 300),
              new AckRange(1, 19)
            )
            strictEqual(frame.numWritableNackRanges(), 2)

            let buf = frame.toBuffer()
            let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
            ok(ackFrame.largestAcked === 300)
            ok(ackFrame.lowestAcked === 1)
            strictEqual(ackFrame.hasMissingRanges(), true)
            strictEqual(ackFrame.ackRanges.length, 2)
            deepEqual(ackFrame.ackRanges[0], new AckRange(20 + 255, 300))
            deepEqual(ackFrame.ackRanges[1], new AckRange(1, 19))
          })

          it('two block for 256 lost packets', function () {
            let frame = new AckFrame()
            frame.largestAcked = 300
            frame.lowestAcked = 1
            frame.ackRanges.push(
              new AckRange(20 + 256, 300),
              new AckRange(1, 19)
            )
            strictEqual(frame.numWritableNackRanges(), 3)

            let buf = frame.toBuffer()
            let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
            ok(ackFrame.largestAcked === 300)
            ok(ackFrame.lowestAcked === 1)
            strictEqual(ackFrame.hasMissingRanges(), true)
            strictEqual(ackFrame.ackRanges.length, 2)
            deepEqual(ackFrame.ackRanges[0], new AckRange(20 + 256, 300))
            deepEqual(ackFrame.ackRanges[1], new AckRange(1, 19))
          })

          it('two block for 510 lost packets', function () {
            let frame = new AckFrame()
            frame.largestAcked = 600
            frame.lowestAcked = 1
            frame.ackRanges.push(
              new AckRange(20 + 510, 600),
              new AckRange(1, 19)
            )
            strictEqual(frame.numWritableNackRanges(), 3)

            let buf = frame.toBuffer()
            let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
            ok(ackFrame.largestAcked === 600)
            ok(ackFrame.lowestAcked === 1)
            strictEqual(ackFrame.hasMissingRanges(), true)
            strictEqual(ackFrame.ackRanges.length, 2)
            deepEqual(ackFrame.ackRanges[0], new AckRange(20 + 510, 600))
            deepEqual(ackFrame.ackRanges[1], new AckRange(1, 19))
          })

          it('two block for 511 lost packets', function () {
            let frame = new AckFrame()
            frame.largestAcked = 600
            frame.lowestAcked = 1
            frame.ackRanges.push(
              new AckRange(20 + 511, 600),
              new AckRange(1, 19)
            )
            strictEqual(frame.numWritableNackRanges(), 4)

            let buf = frame.toBuffer()
            let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
            ok(ackFrame.largestAcked === 600)
            ok(ackFrame.lowestAcked === 1)
            strictEqual(ackFrame.hasMissingRanges(), true)
            strictEqual(ackFrame.ackRanges.length, 2)
            deepEqual(ackFrame.ackRanges[0], new AckRange(20 + 511, 600))
            deepEqual(ackFrame.ackRanges[1], new AckRange(1, 19))
          })

          it('two block for 512 lost packets', function () {
            let frame = new AckFrame()
            frame.largestAcked = 600
            frame.lowestAcked = 1
            frame.ackRanges.push(
              new AckRange(20 + 512, 600),
              new AckRange(1, 19)
            )
            strictEqual(frame.numWritableNackRanges(), 4)

            let buf = frame.toBuffer()
            let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
            ok(ackFrame.largestAcked === 600)
            ok(ackFrame.lowestAcked === 1)
            strictEqual(ackFrame.hasMissingRanges(), true)
            strictEqual(ackFrame.ackRanges.length, 2)
            deepEqual(ackFrame.ackRanges[0], new AckRange(20 + 512, 600))
            deepEqual(ackFrame.ackRanges[1], new AckRange(1, 19))
          })

          it('multiple blocks for a lot of lost packets', function () {
            let frame = new AckFrame()
            frame.largestAcked = 3000
            frame.lowestAcked = 1
            frame.ackRanges.push(
              new AckRange(2900, 3000),
              new AckRange(1, 19)
            )

            let buf = frame.toBuffer()
            let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
            ok(ackFrame.largestAcked === 3000)
            ok(ackFrame.lowestAcked === 1)
            strictEqual(ackFrame.hasMissingRanges(), true)
            strictEqual(ackFrame.ackRanges.length, 2)
            deepEqual(ackFrame.ackRanges[0], new AckRange(2900, 3000))
            deepEqual(ackFrame.ackRanges[1], new AckRange(1, 19))
          })

          it('multiple longer blocks for 256 lost packets', function () {
            let frame = new AckFrame()
            frame.largestAcked = 3600
            frame.lowestAcked = 1
            frame.ackRanges.push(
              new AckRange(2900, 3600),
              new AckRange(1000, 2500),
              new AckRange(1, 19)
            )

            let buf = frame.toBuffer()
            let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
            ok(ackFrame.largestAcked === 3600)
            ok(ackFrame.lowestAcked === 1)
            strictEqual(ackFrame.hasMissingRanges(), true)
            strictEqual(ackFrame.ackRanges.length, 3)
            deepEqual(ackFrame.ackRanges[0], new AckRange(2900, 3600))
            deepEqual(ackFrame.ackRanges[1], new AckRange(1000, 2500))
            deepEqual(ackFrame.ackRanges[2], new AckRange(1, 19))
          })
        })

        suite('longer ACK blocks', function () {
          it('a 1 byte Missing Sequence Number Delta', function () {
            let frame = new AckFrame()
            frame.largestAcked = 200
            frame.lowestAcked = 1

            let buf = frame.toBuffer()
            strictEqual(buf[0] & 0x3, 0x0)
            let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
            ok(ackFrame.largestAcked === 200)
            ok(ackFrame.lowestAcked === 1)
          })

          it('a 2 byte Missing Sequence Number Delta', function () {
            let frame = new AckFrame()
            frame.largestAcked = 0x100
            frame.lowestAcked = 1

            let buf = frame.toBuffer()
            strictEqual(buf[0] & 0x3, 0x1)
            let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
            ok(ackFrame.largestAcked === 0x100)
            ok(ackFrame.lowestAcked === 1)
          })

          it('a 4 byte Missing Sequence Number Delta', function () {
            let frame = new AckFrame()
            frame.largestAcked = 0x10000
            frame.lowestAcked = 1

            let buf = frame.toBuffer()
            strictEqual(buf[0] & 0x3, 0x2)
            let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
            ok(ackFrame.largestAcked === 0x10000)
            ok(ackFrame.lowestAcked === 1)
          })

          it('a 6 byte Missing Sequence Number Delta', function () {
            let frame = new AckFrame()
            frame.largestAcked = 0x100000000
            frame.lowestAcked = 1

            let buf = frame.toBuffer()
            strictEqual(buf[0] & 0x3, 0x3)
            let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
            ok(ackFrame.largestAcked === 0x100000000)
            ok(ackFrame.lowestAcked === 1)
          })

          it('a 1 byte Missing Sequence Number Delta, if all ACK blocks are short', function () {
            let frame = new AckFrame()
            frame.largestAcked = 5001
            frame.lowestAcked = 1
            frame.ackRanges.push(
              new AckRange(5000, 5001),
              new AckRange(250, 300),
              new AckRange(1, 200)
            )

            let buf = frame.toBuffer()
            strictEqual(buf[0] & 0x3, 0x0)
            let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
            ok(ackFrame.largestAcked === 5001)
            ok(ackFrame.lowestAcked === 1)
            strictEqual(ackFrame.hasMissingRanges(), true)
            strictEqual(ackFrame.ackRanges.length, 3)
            deepEqual(ackFrame.ackRanges[0], new AckRange(5000, 5001))
            deepEqual(ackFrame.ackRanges[1], new AckRange(250, 300))
            deepEqual(ackFrame.ackRanges[2], new AckRange(1, 200))
          })

          it('a 2 byte Missing Sequence Number Delta, for a frame with 2 ACK ranges', function () {
            let frame = new AckFrame()
            frame.largestAcked = 10000
            frame.lowestAcked = 1
            frame.ackRanges.push(
              new AckRange(9990, 10000),
              new AckRange(1, 256)
            )

            let buf = frame.toBuffer()
            strictEqual(buf[0] & 0x3, 0x1)
            let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
            ok(ackFrame.largestAcked === 10000)
            ok(ackFrame.lowestAcked === 1)
            strictEqual(ackFrame.hasMissingRanges(), true)
            strictEqual(ackFrame.ackRanges.length, 2)
            deepEqual(ackFrame.ackRanges[0], new AckRange(9990, 10000))
            deepEqual(ackFrame.ackRanges[1], new AckRange(1, 256))
          })
        })

        suite('too many ACK blocks', function () {
          it('skips the lowest ACK ranges, if there are more than 255 AckRanges', function () {
            let ackRanges = new Array(300)
            for (let i = 1; i <= 300; i++) {
              ackRanges[300 - i] = new AckRange(3 * i, 3 * i + 1)
            }
            let frame = new AckFrame()
            frame.largestAcked = ackRanges[0].lastNum
            frame.lowestAcked = ackRanges[ackRanges.length - 1].firstNum
            frame.ackRanges = ackRanges

            let buf = frame.toBuffer()
            let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
            ok(ackFrame.largestAcked === frame.largestAcked)
            ok(ackFrame.lowestAcked === ackRanges[254].firstNum)
            strictEqual(ackFrame.ackRanges.length, 0xff)
            strictEqual(ackFrame.validateAckRanges(), true)
          })

          it('skips the lowest ACK ranges, if the gaps are large', function () {
            let ackRanges = new Array(100)
            // every AckRange will take 4 written ACK ranges
            for (let i = 1; i <= 100; i++) {
              ackRanges[100 - i] = new AckRange(1000 * i, 1000 * i + 1)
            }
            let frame = new AckFrame()
            frame.largestAcked = ackRanges[0].lastNum
            frame.lowestAcked = ackRanges[ackRanges.length - 1].firstNum
            frame.ackRanges = ackRanges

            let buf = frame.toBuffer()
            let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
            ok(ackFrame.largestAcked === frame.largestAcked)
            ok(ackFrame.lowestAcked === ackRanges[ackFrame.ackRanges.length - 1].firstNum)
            strictEqual(ackFrame.ackRanges.length, 256 / 4)
            strictEqual(ackFrame.validateAckRanges(), true)
          })

          it('works with huge gaps', function () {
            let ackRanges = [
              new AckRange(2 * 255 * 200, 2 * 255 * 200 + 1),
              new AckRange(1 * 255 * 200, 1 * 255 * 200 + 1),
              new AckRange(1, 2)
            ]
            let frame = new AckFrame()
            frame.largestAcked = ackRanges[0].lastNum
            frame.lowestAcked = ackRanges[ackRanges.length - 1].firstNum
            frame.ackRanges = ackRanges

            let buf = frame.toBuffer()
            let ackFrame = AckFrame.fromBuffer(Visitor.wrap(buf))
            ok(ackFrame.largestAcked === frame.largestAcked)
            ok(ackFrame.lowestAcked === ackRanges[ackFrame.ackRanges.length - 1].firstNum)
            strictEqual(ackFrame.ackRanges.length, 2)
            strictEqual(ackFrame.validateAckRanges(), true)
          })
        })
      })
    })

    suite('ACK range validator', function () {
      it('accepts an ACK without NACK Ranges', function () {
        let frame = new AckFrame()
        frame.largestAcked = 7
        strictEqual(frame.validateAckRanges(), true)
      })

      it('rejects ACK ranges with a single range', function () {
        let frame = new AckFrame()
        frame.largestAcked = 10
        frame.ackRanges.push(new AckRange(1, 10))
        strictEqual(frame.validateAckRanges(), false)
      })

      it('rejects ACK ranges with LastPacketNumber of the first range unequal to LargestObserved', function () {
        let frame = new AckFrame()
        frame.largestAcked = 10
        frame.ackRanges.push(
          new AckRange(8, 9),
          new AckRange(2, 3)
        )
        strictEqual(frame.validateAckRanges(), false)
      })

      it('rejects ACK ranges with FirstPacketNumber greater than LastPacketNumber', function () {
        let frame = new AckFrame()
        frame.largestAcked = 10
        frame.ackRanges.push(
          new AckRange(8, 10),
          new AckRange(4, 3)
        )
        strictEqual(frame.validateAckRanges(), false)
      })

      it('rejects ACK ranges with FirstPacketNumber greater than LargestObserved', function () {
        let frame = new AckFrame()
        frame.largestAcked = 5
        frame.ackRanges.push(
          new AckRange(4, 10),
          new AckRange(1, 2)
        )
        strictEqual(frame.validateAckRanges(), false)
      })

      it('rejects ACK ranges in the wrong order', function () {
        let frame = new AckFrame()
        frame.largestAcked = 7
        frame.ackRanges.push(
          new AckRange(2, 2),
          new AckRange(6, 7)
        )
        strictEqual(frame.validateAckRanges(), false)
      })

      it('rejects with overlapping ACK ranges', function () {
        let frame = new AckFrame()
        frame.largestAcked = 7
        frame.ackRanges.push(
          new AckRange(5, 7),
          new AckRange(2, 5)
        )
        strictEqual(frame.validateAckRanges(), false)
      })

      it('rejects ACK ranges that are part of a larger ACK range', function () {
        let frame = new AckFrame()
        frame.largestAcked = 7
        frame.ackRanges.push(
          new AckRange(4, 7),
          new AckRange(5, 6)
        )
        strictEqual(frame.validateAckRanges(), false)
      })

      it('rejects with directly adjacent ACK ranges', function () {
        let frame = new AckFrame()
        frame.largestAcked = 7
        frame.ackRanges.push(
          new AckRange(5, 7),
          new AckRange(2, 4)
        )
        strictEqual(frame.validateAckRanges(), false)
      })

      it('accepts an ACK with one lost packet', function () {
        let frame = new AckFrame()
        frame.largestAcked = 10
        frame.ackRanges.push(
          new AckRange(5, 10),
          new AckRange(1, 3)
        )
        strictEqual(frame.validateAckRanges(), true)
      })

      it('accepts an ACK with multiple lost packets', function () {
        let frame = new AckFrame()
        frame.largestAcked = 20
        frame.ackRanges.push(
          new AckRange(15, 20),
          new AckRange(10, 12),
          new AckRange(1, 3)
        )
        strictEqual(frame.validateAckRanges(), true)
      })
    })

    suite('check if ACK frame acks a certain packet', function () {
      it('works with an ACK without any ranges', function () {
        let frame = new AckFrame()
        frame.largestAcked = 10
        frame.lowestAcked = 5
        strictEqual(frame.acksPacket(1), false)
        strictEqual(frame.acksPacket(4), false)
        strictEqual(frame.acksPacket(5), true)
        strictEqual(frame.acksPacket(8), true)
        strictEqual(frame.acksPacket(10), true)
        strictEqual(frame.acksPacket(11), false)
        strictEqual(frame.acksPacket(20), false)
      })

      it('works with an ACK with multiple ACK ranges', function () {
        let frame = new AckFrame()
        frame.largestAcked = 20
        frame.lowestAcked = 5
        frame.ackRanges.push(
          new AckRange(15, 20),
          new AckRange(5, 8)
        )
        strictEqual(frame.acksPacket(4), false)
        strictEqual(frame.acksPacket(5), true)
        strictEqual(frame.acksPacket(7), true)
        strictEqual(frame.acksPacket(8), true)
        strictEqual(frame.acksPacket(9), false)
        strictEqual(frame.acksPacket(14), false)
        strictEqual(frame.acksPacket(15), true)
        strictEqual(frame.acksPacket(18), true)
        strictEqual(frame.acksPacket(20), true)
        strictEqual(frame.acksPacket(21), false)
      })
    })
  })

  suite('STOP_WAITING Frame', function () {
    it('new StopWaitingFrame', function () {
      let headerPacketNumber = new PacketNumber(bufferFromBytes([0xff, 0x1f]))
      let leastUnackedPacketNumber = new PacketNumber(bufferFromBytes([0xff, 0x0f]))
      let stopWaitingFrame = new StopWaitingFrame(headerPacketNumber, leastUnackedPacketNumber)

      strictEqual(stopWaitingFrame.type, 6)
      ok(leastUnackedPacketNumber.equals(stopWaitingFrame.leastUnacked))
      let buf = stopWaitingFrame.toBuffer()
      ok(buf.equals(bufferFromBytes([
        0x06,
        0x00, 0x10
      ])))
      ok(buf.equals(StopWaitingFrame.fromBuffer(Visitor.wrap(buf), headerPacketNumber).toBuffer()))
    })
  })

  suite('WINDOW_UPDATE Frame', function () {
    it('new WindowUpdateFrame with StreamID(0)', function () {
      let streamID = StreamID.fromValue(0)
      let offset = new Offset(bufferFromBytes([0xff, 0xff, 0xff, 0xff]))
      let windowUpdateFrame = new WindowUpdateFrame(streamID, offset)

      strictEqual(windowUpdateFrame.type, 4)
      let buf = windowUpdateFrame.toBuffer()
      ok(buf.equals(bufferFromBytes([
        0x04,
        0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00
      ])))
      ok(buf.equals(WindowUpdateFrame.fromBuffer(Visitor.wrap(buf)).toBuffer()))
    })
  })

  suite('BLOCKED Frame', function () {
    it('new BlockedFrame with StreamID(0)', function () {
      let streamID = StreamID.fromValue(0)
      let blockedFrame = new BlockedFrame(streamID)

      strictEqual(blockedFrame.type, 5)
      let buf = blockedFrame.toBuffer()
      ok(buf.equals(bufferFromBytes([
        0x05,
        0x00, 0x00, 0x00, 0x00
      ])))
      ok(buf.equals(BlockedFrame.fromBuffer(Visitor.wrap(buf)).toBuffer()))
    })
  })

  suite('CONGESTION_FEEDBACK Frame', function () {
    it('new CongestionFeedbackFrame', function () {
      let congestionFeedbackFrame = new CongestionFeedbackFrame(0b00100000)

      strictEqual(congestionFeedbackFrame.type, 32)
      let buf = congestionFeedbackFrame.toBuffer()
      ok(buf.equals(bufferFromBytes([0b00100000])))
      ok(buf.equals(CongestionFeedbackFrame.fromBuffer(Visitor.wrap(buf)).toBuffer()))
    })

    it('when invalid CongestionFeedbackFrame type', function () {
      throws(() => CongestionFeedbackFrame.fromBuffer(Visitor.wrap(bufferFromBytes([0b01100000]))),
        /INVALID_FRAME_DATA/)
    })
  })

  suite('PADDING Frame', function () {
    it('new PaddingFrame', function () {
      let paddingFrame = new PaddingFrame()

      strictEqual(paddingFrame.type, 0)
      let buf = paddingFrame.toBuffer()
      ok(buf.equals(bufferFromBytes([0x00])))
      ok(buf.equals(PaddingFrame.fromBuffer(Visitor.wrap(buf)).toBuffer()))
    })
  })

  suite('RST_STREAM Frame', function () {
    it('new RstStreamFrame', function () {
      let streamID = StreamID.fromValue(1)
      let error = new QuicError(1)
      let offset = new Offset(
        bufferFromBytes([0x01, 0x2, 0x03, 0x04, 0x05, 0x06]))
      let rstStreamFrame = new RstStreamFrame(streamID, offset, error)

      strictEqual(rstStreamFrame.type, 1)
      let buf = rstStreamFrame.toBuffer()
      ok(buf.equals(bufferFromBytes([
        0x01,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00
      ])))
      ok(buf.equals(RstStreamFrame.fromBuffer(Visitor.wrap(buf)).toBuffer()))
    })
  })

  suite('PING frame', function () {
    it('new PingFrame', function () {
      let pingFrame = new PingFrame()

      strictEqual(pingFrame.type, 7)
      let buf = pingFrame.toBuffer()
      ok(buf.equals(bufferFromBytes([0x07])))
      ok(buf.equals(PingFrame.fromBuffer(Visitor.wrap(buf)).toBuffer()))
    })
  })

  suite('CONNECTION_CLOSE frame', function () {
    it('new ConnectionCloseFrame with QuicError(0)', function () {
      let error = new QuicError(0)
      let connectionCloseFrame = new ConnectionCloseFrame(error)

      strictEqual(connectionCloseFrame.type, 2)
      let buf = connectionCloseFrame.toBuffer()
      ok(buf.equals(bufferFromBytes([
        0x02,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
      ])))
      ok(buf.equals(ConnectionCloseFrame.fromBuffer(Visitor.wrap(buf)).toBuffer()))
    })

    it('new ConnectionCloseFrame with QuicError(1)', function () {
      let error = new QuicError(1)
      let connectionCloseFrame = new ConnectionCloseFrame(error)

      strictEqual(connectionCloseFrame.type, 2)
      let buf = connectionCloseFrame.toBuffer()
      ok(buf.equals(bufferFromBytes([
        0x02,
        0x01, 0x00, 0x00, 0x00,
        0x28, 0x00,
        'Connection has reached an invalid state.'
      ])))
      ok(buf.equals(ConnectionCloseFrame.fromBuffer(Visitor.wrap(buf)).toBuffer()))
    })
  })

  suite('GOAWAY Frame', function () {
    it('new GoAwayFrame with QuicError(0)', function () {
      let error = new QuicError(0)
      let streamID = StreamID.fromValue(7)
      let goAwayFrame = new GoAwayFrame(streamID, error)

      strictEqual(goAwayFrame.type, 3)
      let buf = goAwayFrame.toBuffer()
      ok(buf.equals(bufferFromBytes([
        0x03,
        0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00,
        0x00, 0x00
      ])))
      ok(buf.equals(GoAwayFrame.fromBuffer(Visitor.wrap(buf)).toBuffer()))
    })

    it('new GoAwayFrame with QuicError(1)', function () {
      let error = new QuicError(1)
      let streamID = StreamID.fromValue(7)
      let goAwayFrame = new GoAwayFrame(streamID, error)

      strictEqual(goAwayFrame.type, 3)
      let buf = goAwayFrame.toBuffer()
      ok(buf.equals(bufferFromBytes([
        0x03,
        0x01, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00,
        0x28, 0x00,
        'Connection has reached an invalid state.'
      ])))
      ok(buf.equals(GoAwayFrame.fromBuffer(Visitor.wrap(buf)).toBuffer()))
    })
  })
})
