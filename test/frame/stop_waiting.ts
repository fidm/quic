'use strict'

// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

import { suite, it } from 'tman'
import { ok, strictEqual, deepEqual, throws } from 'assert'

import { Visitor, toBuffer } from '../../src/internal/common'
import { QuicError } from '../../src/internal/error'
import { StreamID, Offset, PacketNumber } from '../../src/internal/protocol'
import {
  parseFrame, StreamFrame, AckFrame, AckRange, PaddingFrame,
  RstStreamFrame, ConnectionCloseFrame, GoAwayFrame,
  WindowUpdateFrame, BlockedFrame, StopWaitingFrame,
  PingFrame, CongestionFeedbackFrame,
} from '../../src/internal/frame'

import { bufferFromBytes } from '../common'

suite('STOP_WAITING Frame', function () {
  it('new StopWaitingFrame', function () {
    const headerPacketNumber = PacketNumber.fromBuffer(bufferFromBytes([0xff, 0x1f]), 2)
    const leastUnacked = PacketNumber.fromBuffer(bufferFromBytes([0xff, 0x0f]), 2).valueOf()
    const stopWaitingFrame = new StopWaitingFrame(headerPacketNumber, leastUnacked)

    strictEqual(stopWaitingFrame.type, 6)
    strictEqual(leastUnacked, stopWaitingFrame.leastUnacked)
    const buf = toBuffer(stopWaitingFrame)
    ok(buf.equals(bufferFromBytes([
      0x06,
      0x00, 0x10,
    ])))
    ok(buf.equals(toBuffer(StopWaitingFrame.fromBuffer(buf, headerPacketNumber))))
  })

  it('parse with parseFrame', function () {
    const headerPacketNumber = PacketNumber.fromBuffer(bufferFromBytes([0xff, 0x1f]), 2)
    const leastUnacked = PacketNumber.fromBuffer(bufferFromBytes([0xff, 0x0f]), 2).valueOf()
    const stopWaitingFrame = new StopWaitingFrame(headerPacketNumber, leastUnacked)

    strictEqual(stopWaitingFrame.type, 6)
    strictEqual(leastUnacked, stopWaitingFrame.leastUnacked)
    const buf = toBuffer(stopWaitingFrame)
    ok(buf.equals(bufferFromBytes([
      0x06,
      0x00, 0x10,
    ])))
    ok(buf.equals(toBuffer(parseFrame(buf, headerPacketNumber))))
  })
})
