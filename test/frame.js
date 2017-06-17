'use strict'

// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const { suite, it } = require('tman')
const { ok, strictEqual, deepEqual, throws } = require('assert')

const QuicID = require('../lib/id')
const QuicFrame = require('../lib/frame')
const { QuicError } = require('../lib/error')
const { bufferFromBytes } = require('./util')

suite('QuicFrame', function () {
  suite('PaddingFrame', function () {
    const PaddingFrame = QuicFrame.PaddingFrame

    it('new PaddingFrame', function () {
      let paddingFrame = new PaddingFrame()

      strictEqual(paddingFrame.type, 0)
      ok(paddingFrame.toBuffer().equals(bufferFromBytes([0x00])))
      deepEqual(paddingFrame, PaddingFrame.fromBuffer(paddingFrame.toBuffer()))
    })
  })

  suite('ResetStreamFrame', function () {
    const ResetStreamFrame = QuicFrame.ResetStreamFrame

    it('new ResetStreamFrame', function () {
      let streamID = QuicID.StreamID.fromValue(1)
      let error = new QuicError(1)
      let offset = new QuicID.Offset(
        bufferFromBytes([0x01, 0x2, 0x03, 0x04, 0x05, 0x06]))
      let resetStreamFrame = new ResetStreamFrame(streamID, offset, error)

      strictEqual(resetStreamFrame.type, 1)
      ok(resetStreamFrame.toBuffer().equals(bufferFromBytes([
        0x01,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00
      ])))
      deepEqual(resetStreamFrame, ResetStreamFrame.fromBuffer(resetStreamFrame.toBuffer()))
    })
  })

  suite('ConnectionCloseFrame', function () {
    const ConnectionCloseFrame = QuicFrame.ConnectionCloseFrame

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

  suite('GoAwayFrame', function () {
    const GoAwayFrame = QuicFrame.GoAwayFrame

    it('new GoAwayFrame with QuicError(0)', function () {
      let error = new QuicError(0)
      let streamID = QuicID.StreamID.fromValue(7)
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
      let streamID = QuicID.StreamID.fromValue(7)
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

  suite('WindowUpdateFrame', function () {
    const WindowUpdateFrame = QuicFrame.WindowUpdateFrame

    it('new WindowUpdateFrame with StreamID(0)', function () {
      let streamID = QuicID.StreamID.fromValue(0)
      let offset = new QuicID.Offset(bufferFromBytes([0xff, 0xff, 0xff, 0xff]))
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

  suite('BlockedFrame', function () {
    const BlockedFrame = QuicFrame.BlockedFrame

    it('new BlockedFrame with StreamID(0)', function () {
      let streamID = QuicID.StreamID.fromValue(0)
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

  suite('StopWaitingFrame', function () {
    const StopWaitingFrame = QuicFrame.StopWaitingFrame

    it('new StopWaitingFrame', function () {
      let headerPacketNumber = new QuicID.PacketNumber(bufferFromBytes([0xff, 0x1f]))
      let leastUnackedPacketNumber = new QuicID.PacketNumber(bufferFromBytes([0xff, 0x0f]))
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

  suite('PingFrame', function () {
    const PingFrame = QuicFrame.PingFrame

    it('new PingFrame', function () {
      let pingFrame = new PingFrame()

      strictEqual(pingFrame.type, 7)
      ok(pingFrame.toBuffer().equals(bufferFromBytes([0x07])))
      deepEqual(pingFrame, PingFrame.fromBuffer(pingFrame.toBuffer()))
    })
  })

  suite('CongestionFrame', function () {
    const CongestionFrame = QuicFrame.CongestionFrame

    it('new CongestionFrame', function () {
      let congestionFrame = new CongestionFrame(0b00100000)

      strictEqual(congestionFrame.type, 32)
      ok(congestionFrame.toBuffer().equals(bufferFromBytes([0b00100000])))
      deepEqual(congestionFrame, CongestionFrame.fromBuffer(congestionFrame.toBuffer()))
    })

    it('when invalid CongestionFrame type', function () {
      throws(() => CongestionFrame.fromBuffer(bufferFromBytes([0b01100000])),
        /INVALID_FRAME_DATA/)
    })
  })

  suite('StreamFrame', function () {
    const StreamFrame = QuicFrame.StreamFrame

    it('new StreamFrame', function () {
      let streamID = QuicID.StreamID.fromValue(1)
      let offset = QuicID.Offset.fromValue(0)
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
      let streamID = QuicID.StreamID.fromValue(1)
      let offset = QuicID.Offset.fromValue(0)
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
})
