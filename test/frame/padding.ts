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

suite('PADDING Frame', function () {
  it('new PaddingFrame', function () {
    const paddingFrame = new PaddingFrame()

    strictEqual(paddingFrame.type, 0)
    const buf = toBuffer(paddingFrame)
    ok(buf.equals(bufferFromBytes([0x00])))
    ok(buf.equals(toBuffer(PaddingFrame.fromBuffer(new BufferVisitor(buf)))))
  })

  it('parse with parseFrame', function () {
    const paddingFrame = new PaddingFrame()

    strictEqual(paddingFrame.type, 0)
    const buf = toBuffer(paddingFrame)
    ok(buf.equals(bufferFromBytes([0x00])))
    ok(buf.equals(toBuffer(parseFrame(new BufferVisitor(buf), new PacketNumber(1)))))
  })
})
