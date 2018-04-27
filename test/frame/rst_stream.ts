'use strict'

// **Github:** https://github.com/toajs/quic
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

suite('RST_STREAM Frame', function () {
  it('new RstStreamFrame', function () {
    const streamID = new StreamID(1)
    const error = new QuicError(1)
    const offset = Offset.fromBuffer(
      new BufferVisitor(bufferFromBytes([0x01, 0x2, 0x03, 0x04, 0x05, 0x06])), 6)
    const rstStreamFrame = new RstStreamFrame(streamID, offset, error)

    strictEqual(rstStreamFrame.type, 1)
    const buf = toBuffer(rstStreamFrame)
    ok(buf.equals(bufferFromBytes([
      0x01,
      0x01, 0x00, 0x00, 0x00,
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00,
      0x01, 0x00, 0x00, 0x00,
    ])))
    ok(buf.equals(toBuffer(RstStreamFrame.fromBuffer(new BufferVisitor(buf)))))
  })

  it('parse with parseFrame', function () {
    const streamID = new StreamID(1)
    const error = new QuicError(1)
    const offset = Offset.fromBuffer(
      new BufferVisitor(bufferFromBytes([0x01, 0x2, 0x03, 0x04, 0x05, 0x06])), 6)
    const rstStreamFrame = new RstStreamFrame(streamID, offset, error)

    strictEqual(rstStreamFrame.type, 1)
    const buf = toBuffer(rstStreamFrame)
    ok(buf.equals(bufferFromBytes([
      0x01,
      0x01, 0x00, 0x00, 0x00,
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x00, 0x00,
      0x01, 0x00, 0x00, 0x00,
    ])))
    ok(buf.equals(toBuffer(parseFrame(new BufferVisitor(buf), new PacketNumber(1)))))
  })
})
