'use strict'

// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const { suite, it } = require('tman')
const { ok, strictEqual, deepEqual, throws } = require('assert')

const { StreamID, Offset, PacketNumber } = require('../lib/protocol')
const { StreamFrame, PaddingFrame, RstStreamFrame, ConnectionCloseFrame, GoAwayFrame, WindowUpdateFrame, BlockedFrame,
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

      strictEqual(streamFrame.type, 0b10100000)
      strictEqual(streamFrame.isFIN, false)
      ok(streamFrame.toBuffer().equals(bufferFromBytes([
        0b10100000,
        0x1,
        0x7, 0x0,
        'abcdefg'
      ])))
      deepEqual(streamFrame, StreamFrame.fromBuffer(streamFrame.toBuffer()))

      streamID = streamID.nextID()
      offset = offset.nextOffset(data.length)
      data = bufferFromBytes(['higklmn'])
      streamFrame = new StreamFrame(streamID, offset, data, false)

      strictEqual(streamFrame.type, 0b10100100)
      strictEqual(streamFrame.isFIN, false)
      ok(streamFrame.toBuffer().equals(bufferFromBytes([
        0b10100100,
        0x3,
        0x7, 0x0,
        0x7, 0x0,
        'higklmn'
      ])))
      deepEqual(streamFrame, StreamFrame.fromBuffer(streamFrame.toBuffer()))

      streamID = streamID.nextID()
      offset = offset.nextOffset(data.length)
      data = bufferFromBytes(['opqrst'])
      streamFrame = new StreamFrame(streamID, offset, data, false)

      strictEqual(streamFrame.type, 0b10100100)
      strictEqual(streamFrame.isFIN, false)
      ok(streamFrame.toBuffer().equals(bufferFromBytes([
        0b10100100,
        0x5,
        0xe, 0x0,
        0x6, 0x0,
        'opqrst'
      ])))
      deepEqual(streamFrame, StreamFrame.fromBuffer(streamFrame.toBuffer()))

      streamID = streamID.nextID()
      offset = offset.nextOffset(data.length)
      data = bufferFromBytes(['uvwxyz'])
      streamFrame = new StreamFrame(streamID, offset, data, true)

      strictEqual(streamFrame.type, 0b11100100)
      strictEqual(streamFrame.isFIN, true)
      ok(streamFrame.toBuffer().equals(bufferFromBytes([
        0b11100100,
        0x7,
        0x14, 0x0,
        0x6, 0x0,
        'uvwxyz'
      ])))
      deepEqual(streamFrame, StreamFrame.fromBuffer(streamFrame.toBuffer()))
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
      deepEqual(streamFrame, StreamFrame.fromBuffer(buf.slice(0, streamFrame.byteLen)))
    })
  })

  suite.skip('ACK Frame', function () {})

  suite('STOP_WAITING Frame', function () {
    it('new StopWaitingFrame', function () {
      let headerPacketNumber = new PacketNumber(bufferFromBytes([0xff, 0x1f]))
      let leastUnackedPacketNumber = new PacketNumber(bufferFromBytes([0xff, 0x0f]))
      let stopWaitingFrame = new StopWaitingFrame(
        headerPacketNumber.delta(leastUnackedPacketNumber), headerPacketNumber.byteLen)

      strictEqual(stopWaitingFrame.type, 6)
      ok(stopWaitingFrame.toBuffer().equals(bufferFromBytes([
        0x06,
        0x00, 0x10
      ])))
      deepEqual(stopWaitingFrame,
        StopWaitingFrame.fromBuffer(stopWaitingFrame.toBuffer(), headerPacketNumber.byteLen))
      ok(leastUnackedPacketNumber.equals(
        stopWaitingFrame.toPacketNumber(headerPacketNumber)))
    })
  })

  suite('WINDOW_UPDATE Frame', function () {
    it('new WindowUpdateFrame with StreamID(0)', function () {
      let streamID = StreamID.fromValue(0)
      let offset = new Offset(bufferFromBytes([0xff, 0xff, 0xff, 0xff]))
      let windowUpdateFrame = new WindowUpdateFrame(streamID, offset)

      strictEqual(windowUpdateFrame.type, 4)
      ok(windowUpdateFrame.toBuffer().equals(bufferFromBytes([
        0x04,
        0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00
      ])))
      deepEqual(windowUpdateFrame,
        WindowUpdateFrame.fromBuffer(windowUpdateFrame.toBuffer()))
    })
  })

  suite('BLOCKED Frame', function () {
    it('new BlockedFrame with StreamID(0)', function () {
      let streamID = StreamID.fromValue(0)
      let blockedFrame = new BlockedFrame(streamID)

      strictEqual(blockedFrame.type, 5)
      ok(blockedFrame.toBuffer().equals(bufferFromBytes([
        0x05,
        0x00, 0x00, 0x00, 0x00
      ])))
      deepEqual(blockedFrame,
        BlockedFrame.fromBuffer(blockedFrame.toBuffer()))
    })
  })

  suite('CONGESTION_FEEDBACK Frame', function () {
    it('new CongestionFeedbackFrame', function () {
      let congestionFeedbackFrame = new CongestionFeedbackFrame(0b00100000)

      strictEqual(congestionFeedbackFrame.type, 32)
      ok(congestionFeedbackFrame.toBuffer().equals(bufferFromBytes([0b00100000])))
      deepEqual(congestionFeedbackFrame, CongestionFeedbackFrame.fromBuffer(congestionFeedbackFrame.toBuffer()))
    })

    it('when invalid CongestionFeedbackFrame type', function () {
      throws(() => CongestionFeedbackFrame.fromBuffer(bufferFromBytes([0b01100000])),
        /INVALID_FRAME_DATA/)
    })
  })

  suite('PADDING Frame', function () {
    it('new PaddingFrame', function () {
      let paddingFrame = new PaddingFrame()

      strictEqual(paddingFrame.type, 0)
      ok(paddingFrame.toBuffer().equals(bufferFromBytes([0x00])))
      deepEqual(paddingFrame, PaddingFrame.fromBuffer(paddingFrame.toBuffer()))
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
      ok(rstStreamFrame.toBuffer().equals(bufferFromBytes([
        0x01,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00
      ])))
      deepEqual(rstStreamFrame, RstStreamFrame.fromBuffer(rstStreamFrame.toBuffer()))
    })
  })

  suite('PING frame', function () {
    it('new PingFrame', function () {
      let pingFrame = new PingFrame()

      strictEqual(pingFrame.type, 7)
      ok(pingFrame.toBuffer().equals(bufferFromBytes([0x07])))
      deepEqual(pingFrame, PingFrame.fromBuffer(pingFrame.toBuffer()))
    })
  })

  suite('CONNECTION_CLOSE frame', function () {
    it('new ConnectionCloseFrame with QuicError(0)', function () {
      let error = new QuicError(0)
      let connectionCloseFrame = new ConnectionCloseFrame(error)

      strictEqual(connectionCloseFrame.type, 2)
      ok(connectionCloseFrame.toBuffer().equals(bufferFromBytes([
        0x02,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
      ])))
      deepEqual(connectionCloseFrame,
        ConnectionCloseFrame.fromBuffer(connectionCloseFrame.toBuffer()))
    })

    it('new ConnectionCloseFrame with QuicError(1)', function () {
      let error = new QuicError(1)
      let connectionCloseFrame = new ConnectionCloseFrame(error)

      strictEqual(connectionCloseFrame.type, 2)
      ok(connectionCloseFrame.toBuffer().equals(bufferFromBytes([
        0x02,
        0x01, 0x00, 0x00, 0x00,
        0x28, 0x00,
        'Connection has reached an invalid state.'
      ])))
      deepEqual(connectionCloseFrame,
        ConnectionCloseFrame.fromBuffer(connectionCloseFrame.toBuffer()))
    })
  })

  suite('GOAWAY Frame', function () {
    it('new GoAwayFrame with QuicError(0)', function () {
      let error = new QuicError(0)
      let streamID = StreamID.fromValue(7)
      let goAwayFrame = new GoAwayFrame(error, streamID)

      strictEqual(goAwayFrame.type, 3)
      ok(goAwayFrame.toBuffer().equals(bufferFromBytes([
        0x03,
        0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00,
        0x00, 0x00
      ])))
      deepEqual(goAwayFrame, GoAwayFrame.fromBuffer(goAwayFrame.toBuffer()))
    })

    it('new GoAwayFrame with QuicError(1)', function () {
      let error = new QuicError(1)
      let streamID = StreamID.fromValue(7)
      let goAwayFrame = new GoAwayFrame(error, streamID)

      strictEqual(goAwayFrame.type, 3)
      ok(goAwayFrame.toBuffer().equals(bufferFromBytes([
        0x03,
        0x01, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00,
        0x28, 0x00,
        'Connection has reached an invalid state.'
      ])))
      deepEqual(goAwayFrame, GoAwayFrame.fromBuffer(goAwayFrame.toBuffer()))
    })
  })
})
