'use strict'

// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const tman = require('tman')
const assert = require('assert')
const QuicID = require('../lib/id')
const QuicFrame = require('../lib/frame')
const QuicError = require('../lib/error')
const bufferFromBytes = require('./util').bufferFromBytes

tman.suite('QuicFrame', function () {
  tman.suite('PaddingFrame', function () {
    const PaddingFrame = QuicFrame.PaddingFrame

    tman.it('new PaddingFrame', function () {
      let paddingFrame = new PaddingFrame()

      assert.strictEqual(paddingFrame.type, 0)
      assert.ok(paddingFrame.toBuffer().equals(bufferFromBytes([0x00])))
      assert.deepEqual(paddingFrame, PaddingFrame.fromBuffer(paddingFrame.toBuffer()))
    })
  })

  tman.suite('ResetStreamFrame', function () {
    const ResetStreamFrame = QuicFrame.ResetStreamFrame

    tman.it('new ResetStreamFrame', function () {
      let streamId = QuicID.StreamId.fromId(1)
      let error = new QuicError(1)
      let offset = bufferFromBytes([0x01, 0x2, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
      let resetStreamFrame = new ResetStreamFrame(streamId, offset, error)

      assert.strictEqual(resetStreamFrame.type, 1)
      assert.ok(resetStreamFrame.toBuffer().equals(bufferFromBytes([
        0x01,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x00, 0x00, 0x00
      ])))
      assert.deepEqual(resetStreamFrame, ResetStreamFrame.fromBuffer(resetStreamFrame.toBuffer()))
    })
  })

  tman.suite('ConnectionCloseFrame', function () {
    const ConnectionCloseFrame = QuicFrame.ConnectionCloseFrame

    tman.it('new ConnectionCloseFrame with QuicError(0)', function () {
      let error = new QuicError(0)
      let connectionCloseFrame = new ConnectionCloseFrame(error)

      assert.strictEqual(connectionCloseFrame.type, 2)
      assert.ok(connectionCloseFrame.toBuffer().equals(bufferFromBytes([
        0x02,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
      ])))
      assert.deepEqual(connectionCloseFrame,
        ConnectionCloseFrame.fromBuffer(connectionCloseFrame.toBuffer()))
    })

    tman.it('new ConnectionCloseFrame with QuicError(1)', function () {
      let error = new QuicError(1)
      let connectionCloseFrame = new ConnectionCloseFrame(error)

      assert.strictEqual(connectionCloseFrame.type, 2)
      assert.ok(connectionCloseFrame.toBuffer().equals(bufferFromBytes([
        0x02,
        0x01, 0x00, 0x00, 0x00,
        0x28, 0x00,
        'Connection has reached an invalid state.'
      ])))
      assert.deepEqual(connectionCloseFrame,
        ConnectionCloseFrame.fromBuffer(connectionCloseFrame.toBuffer()))
    })
  })

  tman.suite('GoAwayFrame', function () {
    const GoAwayFrame = QuicFrame.GoAwayFrame

    tman.it('new GoAwayFrame with QuicError(0)', function () {
      let error = new QuicError(0)
      let streamId = QuicID.StreamId.fromId(7)
      let goAwayFrame = new GoAwayFrame(error, streamId)

      assert.strictEqual(goAwayFrame.type, 3)
      assert.ok(goAwayFrame.toBuffer().equals(bufferFromBytes([
        0x03,
        0x00, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00,
        0x00, 0x00
      ])))
      assert.deepEqual(goAwayFrame, GoAwayFrame.fromBuffer(goAwayFrame.toBuffer()))
    })

    tman.it('new GoAwayFrame with QuicError(1)', function () {
      let error = new QuicError(1)
      let streamId = QuicID.StreamId.fromId(7)
      let goAwayFrame = new GoAwayFrame(error, streamId)

      assert.strictEqual(goAwayFrame.type, 3)
      assert.ok(goAwayFrame.toBuffer().equals(bufferFromBytes([
        0x03,
        0x01, 0x00, 0x00, 0x00,
        0x07, 0x00, 0x00, 0x00,
        0x28, 0x00,
        'Connection has reached an invalid state.'
      ])))
      assert.deepEqual(goAwayFrame, GoAwayFrame.fromBuffer(goAwayFrame.toBuffer()))
    })
  })

  tman.suite('WindowUpdateFrame', function () {
    const WindowUpdateFrame = QuicFrame.WindowUpdateFrame

    tman.it('new WindowUpdateFrame with StreamId(0)', function () {
      let streamId = QuicID.StreamId.fromId(0)
      let offset = bufferFromBytes([0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00])
      let windowUpdateFrame = new WindowUpdateFrame(streamId, offset)

      assert.strictEqual(windowUpdateFrame.type, 4)
      assert.ok(windowUpdateFrame.toBuffer().equals(bufferFromBytes([
        0x04,
        0x00, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00
      ])))
      assert.deepEqual(windowUpdateFrame,
        WindowUpdateFrame.fromBuffer(windowUpdateFrame.toBuffer()))
    })
  })

  tman.suite('BlockedFrame', function () {
    const BlockedFrame = QuicFrame.BlockedFrame

    tman.it('new BlockedFrame with StreamId(0)', function () {
      let streamId = QuicID.StreamId.fromId(0)
      let blockedFrame = new BlockedFrame(streamId)

      assert.strictEqual(blockedFrame.type, 5)
      assert.ok(blockedFrame.toBuffer().equals(bufferFromBytes([
        0x05,
        0x00, 0x00, 0x00, 0x00
      ])))
      assert.deepEqual(blockedFrame,
        BlockedFrame.fromBuffer(blockedFrame.toBuffer()))
    })
  })

  tman.suite('StopWaitingFrame', function () {
    const StopWaitingFrame = QuicFrame.StopWaitingFrame

    tman.it('new StopWaitingFrame', function () {
      let packetNumber = new QuicID.PacketNumber(bufferFromBytes([0xff, 0x1f]))
      let stopWaitingFrame = new StopWaitingFrame(packetNumber)

      assert.strictEqual(stopWaitingFrame.type, 6)
      assert.ok(stopWaitingFrame.toBuffer().equals(bufferFromBytes([
        0x06,
        0xff, 0x1f
      ])))
      assert.deepEqual(stopWaitingFrame,
        StopWaitingFrame.fromBuffer(stopWaitingFrame.toBuffer(), packetNumber.byteLen))
    })
  })

  tman.suite('PingFrame', function () {
    const PingFrame = QuicFrame.PingFrame

    tman.it('new PingFrame', function () {
      let pingFrame = new PingFrame()

      assert.strictEqual(pingFrame.type, 7)
      assert.ok(pingFrame.toBuffer().equals(bufferFromBytes([0x07])))
      assert.deepEqual(pingFrame, PingFrame.fromBuffer(pingFrame.toBuffer()))
    })
  })

  tman.suite('CongestionFrame', function () {
    const CongestionFrame = QuicFrame.CongestionFrame

    tman.it('new CongestionFrame', function () {
      let congestionFrame = new CongestionFrame(0b00100000)

      assert.strictEqual(congestionFrame.type, 32)
      assert.ok(congestionFrame.toBuffer().equals(bufferFromBytes([0b00100000])))
      assert.deepEqual(congestionFrame, CongestionFrame.fromBuffer(congestionFrame.toBuffer()))
    })

    tman.it('when invalid CongestionFrame type', function () {
      assert.throws(() => new CongestionFrame(0b01100000), /INVALID_FRAME_DATA/)
    })
  })
})
