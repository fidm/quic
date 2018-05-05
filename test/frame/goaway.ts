'use strict'

// **Github:** https://github.com/fidm/quic
//
// **License:** MIT

import { suite, it } from 'tman'
import { ok, strictEqual, deepEqual, throws } from 'assert'

import { BufferVisitor, toBuffer } from '../../src/internal/common'
import { QuicError } from '../../src/internal/error'
import { StreamID, Offset, PacketNumber } from '../../src/internal/protocol'
import {
  parseFrame, StreamFrame, AckFrame, AckRange, PaddingFrame,
  RstStreamFrame, ConnectionCloseFrame, GoAwayFrame,
  WindowUpdateFrame, BlockedFrame, StopWaitingFrame,
  PingFrame, CongestionFeedbackFrame,
} from '../../src/internal/frame'

import { bufferFromBytes } from '../common'

suite('GOAWAY Frame', function () {
  it('new GoAwayFrame with QuicError(0)', function () {
    const error = new QuicError(0)
    const streamID = new StreamID(7)
    const goAwayFrame = new GoAwayFrame(streamID, error)

    strictEqual(goAwayFrame.type, 3)
    const buf = toBuffer(goAwayFrame)
    ok(buf.equals(bufferFromBytes([
      0x03,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x07,
      0x00, 0x00,
    ])))
    ok(buf.equals(toBuffer(GoAwayFrame.fromBuffer(new BufferVisitor(buf)))))
  })

  it('new GoAwayFrame with QuicError(1)', function () {
    const error = new QuicError(1)
    const streamID = new StreamID(7)
    const goAwayFrame = new GoAwayFrame(streamID, error)

    strictEqual(goAwayFrame.type, 3)
    const buf = toBuffer(goAwayFrame)
    ok(buf.equals(bufferFromBytes([
      0x03,
      0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x07,
      0x00, 0x28,
      'Connection has reached an invalid state.',
    ])))
    ok(buf.equals(toBuffer(GoAwayFrame.fromBuffer(new BufferVisitor(buf)))))
  })

  it('parse with parseFrame', function () {
    const error = new QuicError(1)
    const streamID = new StreamID(7)
    const goAwayFrame = new GoAwayFrame(streamID, error)

    strictEqual(goAwayFrame.type, 3)
    const buf = toBuffer(goAwayFrame)
    ok(buf.equals(bufferFromBytes([
      0x03,
      0x00, 0x00, 0x00, 0x01,
      0x00, 0x00, 0x00, 0x07,
      0x00, 0x28,
      'Connection has reached an invalid state.',
    ])))
    ok(buf.equals(toBuffer(parseFrame(new BufferVisitor(buf), new PacketNumber(1)))))
  })
})
