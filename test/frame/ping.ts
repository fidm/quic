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

suite('PING frame', function () {
  it('new PingFrame', function () {
    const pingFrame = new PingFrame()

    strictEqual(pingFrame.type, 7)
    const buf = toBuffer(pingFrame)
    ok(buf.equals(bufferFromBytes([0x07])))
    ok(buf.equals(toBuffer(PingFrame.fromBuffer(new BufferVisitor(buf)))))
  })

  it('parse with parseFrame', function () {
    const pingFrame = new PingFrame()

    strictEqual(pingFrame.type, 7)
    const buf = toBuffer(pingFrame)
    ok(buf.equals(bufferFromBytes([0x07])))
    ok(buf.equals(toBuffer(parseFrame(new BufferVisitor(buf), new PacketNumber(1)))))
  })
})
