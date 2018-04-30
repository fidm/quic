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

suite('WINDOW_UPDATE Frame', function () {
  it('new WindowUpdateFrame with StreamID', function () {
    const streamID = new StreamID(10)
    const offset = Offset.fromBuffer(new BufferVisitor(bufferFromBytes([0xff, 0xff, 0xff, 0xff])), 4)
    const windowUpdateFrame = new WindowUpdateFrame(streamID, offset)

    strictEqual(windowUpdateFrame.type, 4)
    const buf = toBuffer(windowUpdateFrame)
    ok(buf.equals(bufferFromBytes([
      0x04,
      0x00, 0x00, 0x00, 0x0a,
      0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    ])))
    ok(buf.equals(toBuffer(WindowUpdateFrame.fromBuffer(new BufferVisitor(buf)))))
  })

  it('parse with parseFrame', function () {
    const streamID = new StreamID(10)
    const offset = Offset.fromBuffer(new BufferVisitor(bufferFromBytes([0xff, 0xff, 0xff, 0xff])), 4)
    const windowUpdateFrame = new WindowUpdateFrame(streamID, offset)

    strictEqual(windowUpdateFrame.type, 4)
    const buf = toBuffer(windowUpdateFrame)
    ok(buf.equals(bufferFromBytes([
      0x04,
      0x00, 0x00, 0x00, 0x0a,
      0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
    ])))
    ok(buf.equals(toBuffer(parseFrame(new BufferVisitor(buf), new PacketNumber(1)))))
  })
})
