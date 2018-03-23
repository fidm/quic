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

suite('BLOCKED Frame', function () {
  it('new BlockedFrame with StreamID', function () {
    const streamID = new StreamID(10)
    const blockedFrame = new BlockedFrame(streamID)

    strictEqual(blockedFrame.type, 5)
    const buf = toBuffer(blockedFrame)
    ok(buf.equals(bufferFromBytes([
      0x05,
      0x0a, 0x00, 0x00, 0x00,
    ])))
    ok(buf.equals(toBuffer(BlockedFrame.fromBuffer(buf))))
  })

  it('parse with parseFrame', function () {
    const streamID = new StreamID(10)
    const blockedFrame = new BlockedFrame(streamID)

    strictEqual(blockedFrame.type, 5)
    const buf = toBuffer(blockedFrame)
    ok(buf.equals(bufferFromBytes([
      0x05,
      0x0a, 0x00, 0x00, 0x00,
    ])))
    ok(buf.equals(toBuffer(parseFrame(buf, new PacketNumber(1)))))
  })
})
