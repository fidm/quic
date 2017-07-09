'use strict'

// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const { suite, it } = require('tman')
const { ok, strictEqual, deepEqual, throws } = require('assert')

const { StreamID, Offset, PacketNumber } = require('../lib/protocol')
const { StreamFrame, AckFrame, PaddingFrame, RstStreamFrame, ConnectionCloseFrame, GoAwayFrame, WindowUpdateFrame, BlockedFrame,
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
      deepEqual(buf, StreamFrame.fromBuffer(buf, 0).toBuffer())

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
      deepEqual(buf, StreamFrame.fromBuffer(buf, 0).toBuffer())

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
      deepEqual(buf, StreamFrame.fromBuffer(buf, 0).toBuffer())

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
      deepEqual(buf, StreamFrame.fromBuffer(buf, 0).toBuffer())
    })

    it('when invalid StreamFrame type', function () {
      let streamID = StreamID.fromValue(1)
      let offset = Offset.fromValue(0)
      let data = bufferFromBytes(['abcd'])
      let streamFrame = new StreamFrame(streamID, offset, data, false)
      let buf = streamFrame.toBuffer()

      throws(() => StreamFrame.fromBuffer(buf.slice(0, 1)), /INVALID_STREAM_DATA/)
      throws(() => StreamFrame.fromBuffer(buf.slice(0, 2)), /INVALID_STREAM_DATA/)
      throws(() => StreamFrame.fromBuffer(buf.slice(0, 3)), /INVALID_STREAM_DATA/)
      throws(() => StreamFrame.fromBuffer(buf.slice(0, 4)), /INVALID_STREAM_DATA/)
      throws(() => StreamFrame.fromBuffer(buf.slice(0, 5)), /INVALID_STREAM_DATA/)
      throws(() => StreamFrame.fromBuffer(buf.slice(0, 6)), /INVALID_STREAM_DATA/)
      throws(() => StreamFrame.fromBuffer(buf.slice(0, 7)), /INVALID_STREAM_DATA/)
      deepEqual(buf, StreamFrame.fromBuffer(buf.slice(0, streamFrame.byteLen), 0).toBuffer())
    })
  })

  suite('ACK Frame', function () {
    suite('parsing', function () {
      it('a sample ACK frame', function () {
        let buf = bufferFromBytes([0b01000000, 0x1c, 0x8e, 0x0, 0x1c, 0x1, 0x1, 0x6b, 0x26, 0x3, 0x0])
        let ackFrame = AckFrame.fromBuffer(buf, 0)
        ok(ackFrame.largestAcked.equals(PacketNumber.fromValue(0x1c)))
        ok(ackFrame.lowestAcked.equals(PacketNumber.fromValue(0x1)))
        ok(ackFrame.delayTime === 142)
        ok(ackFrame.hasMissingRanges() === false)

        // ignore Timestamps
        deepEqual(ackFrame.toBuffer(), bufferFromBytes([0b01000000, 0x1c, 0x8e, 0x0, 0x1c, 0x0]))
      })

      it('a frame without a timestamp', function () {
        let buf = bufferFromBytes([0x40, 0x3, 0x50, 0x15, 0x3, 0x0])
        let ackFrame = AckFrame.fromBuffer(buf, 0)
        ok(ackFrame.largestAcked.equals(PacketNumber.fromValue(0x3)))
        ok(ackFrame.lowestAcked.equals(PacketNumber.fromValue(0x1)))
        ok(ackFrame.delayTime === 6816)
        ok(ackFrame.hasMissingRanges() === false)
      })

      it('a frame where the largest acked is 0', function () {
        let buf = bufferFromBytes([0x40, 0x0, 0xff, 0xff, 0x0, 0x0])
        let ackFrame = AckFrame.fromBuffer(buf, 0)
        ok(ackFrame.largestAcked.equals(PacketNumber.fromValue(0x0)))
        ok(ackFrame.lowestAcked.equals(PacketNumber.fromValue(0x0)))
        ok(ackFrame.hasMissingRanges() === false)
      })

      it('a frame with a 48 bit packet number', function () {
        let buf = bufferFromBytes([0x4c, 0x37, 0x13, 0xad, 0xfb, 0xca, 0xde, 0x0, 0x0, 0x5, 0x1, 0, 0, 0, 0, 0])
        let ackFrame = AckFrame.fromBuffer(buf, 0)
        ok(ackFrame.largestAcked.equals(PacketNumber.fromValue(0xdecafbad1337)))
        ok(ackFrame.lowestAcked.equals(PacketNumber.fromValue(0xdecafbad1337 - 5 + 1)))
        ok(ackFrame.hasMissingRanges() === false)
      })

      it('a frame with 1 ACKed packet', function () {
        let buf = bufferFromBytes([0x40, 0x10, 0x8e, 0x0, 0x1, 0x0])
        let ackFrame = AckFrame.fromBuffer(buf, 0)
        ok(ackFrame.largestAcked.equals(PacketNumber.fromValue(0x10)))
        ok(ackFrame.lowestAcked.equals(PacketNumber.fromValue(0x10)))
        ok(ackFrame.hasMissingRanges() === false)
      })

      it('a frame, when packet 1 was lost', function () {
        let buf = bufferFromBytes([0x40, 0x9, 0x92, 0x7, 0x8, 0x3, 0x2, 0x69, 0xa3, 0x0, 0x0, 0x1, 0xc9, 0x2, 0x0, 0x46, 0x10])
        let ackFrame = AckFrame.fromBuffer(buf, 0)
        ok(ackFrame.largestAcked.equals(PacketNumber.fromValue(9)))
        ok(ackFrame.lowestAcked.equals(PacketNumber.fromValue(2)))
        ok(ackFrame.hasMissingRanges() === false)
      })

      it('a frame with multiple timestamps', function () {
        let buf = bufferFromBytes([0x40, 0x10, 0x0, 0x0, 0x10, 0x4, 0x1, 0x6b, 0x26, 0x4, 0x0, 0x3, 0, 0, 0x2, 0, 0, 0x1, 0, 0])
        let ackFrame = AckFrame.fromBuffer(buf, 0)
        ok(ackFrame.largestAcked.equals(PacketNumber.fromValue(0x10)))
        ok(ackFrame.lowestAcked.equals(PacketNumber.fromValue(1)))
        ok(ackFrame.hasMissingRanges() === false)
      })

      it('errors when the ACK range is too large', function () {
        // LargestAcked: 0x1c
        // Length: 0x1d => LowestAcked would be -1
        throws(() => {
          let buf = bufferFromBytes([0x40, 0x1c, 0x8e, 0x0, 0x1d, 0x1, 0x1, 0x6b, 0x26, 0x3, 0x0])
          AckFrame.fromBuffer(buf, 0)
        })
      })

      it('errors when the first ACK range is empty', function () {
        throws(() => {
          let buf = bufferFromBytes([0x40, 0x9, 0x8e, 0x0, 0x0, 0x1, 0])
          AckFrame.fromBuffer(buf, 0)
        })
      })
    })

    suite('ACK blocks', function () {})
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
      deepEqual(buf, StopWaitingFrame.fromBuffer(buf, 0, headerPacketNumber).toBuffer())
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
      deepEqual(buf, WindowUpdateFrame.fromBuffer(buf, 0).toBuffer())
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
      deepEqual(buf, BlockedFrame.fromBuffer(buf, 0).toBuffer())
    })
  })

  suite('CONGESTION_FEEDBACK Frame', function () {
    it('new CongestionFeedbackFrame', function () {
      let congestionFeedbackFrame = new CongestionFeedbackFrame(0b00100000)

      strictEqual(congestionFeedbackFrame.type, 32)
      let buf = congestionFeedbackFrame.toBuffer()
      ok(buf.equals(bufferFromBytes([0b00100000])))
      deepEqual(buf, CongestionFeedbackFrame.fromBuffer(buf, 0).toBuffer())
    })

    it('when invalid CongestionFeedbackFrame type', function () {
      throws(() => CongestionFeedbackFrame.fromBuffer(bufferFromBytes([0b01100000]), 0),
        /INVALID_FRAME_DATA/)
    })
  })

  suite('PADDING Frame', function () {
    it('new PaddingFrame', function () {
      let paddingFrame = new PaddingFrame()

      strictEqual(paddingFrame.type, 0)
      let buf = paddingFrame.toBuffer()
      ok(buf.equals(bufferFromBytes([0x00])))
      deepEqual(buf, PaddingFrame.fromBuffer(buf, 0).toBuffer())
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
      deepEqual(buf, RstStreamFrame.fromBuffer(buf, 0).toBuffer())
    })
  })

  suite('PING frame', function () {
    it('new PingFrame', function () {
      let pingFrame = new PingFrame()

      strictEqual(pingFrame.type, 7)
      let buf = pingFrame.toBuffer()
      ok(buf.equals(bufferFromBytes([0x07])))
      deepEqual(buf, PingFrame.fromBuffer(buf, 0).toBuffer())
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
      deepEqual(buf, ConnectionCloseFrame.fromBuffer(buf, 0).toBuffer())
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
      deepEqual(buf, ConnectionCloseFrame.fromBuffer(buf, 0).toBuffer())
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
      deepEqual(buf, GoAwayFrame.fromBuffer(buf, 0).toBuffer())
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
      deepEqual(buf, GoAwayFrame.fromBuffer(buf, 0).toBuffer())
    })
  })
})
