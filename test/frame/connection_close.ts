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

suite('CONNECTION_CLOSE frame', function () {
  it('new ConnectionCloseFrame with QuicError(0)', function () {
    const error = new QuicError(0)
    const connectionCloseFrame = new ConnectionCloseFrame(error)

    strictEqual(connectionCloseFrame.type, 2)
    const buf = toBuffer(connectionCloseFrame)
    ok(buf.equals(bufferFromBytes([
      0x02,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00,
    ])))
    ok(buf.equals(toBuffer(ConnectionCloseFrame.fromBuffer(new BufferVisitor(buf)))))
  })

  it('new ConnectionCloseFrame with QuicError(1)', function () {
    const error = new QuicError(1)
    const connectionCloseFrame = new ConnectionCloseFrame(error)

    strictEqual(connectionCloseFrame.type, 2)
    const buf = toBuffer(connectionCloseFrame)
    ok(buf.equals(bufferFromBytes([
      0x02,
      0x01, 0x00, 0x00, 0x00,
      0x28, 0x00,
      'Connection has reached an invalid state.',
    ])))
    ok(buf.equals(toBuffer(ConnectionCloseFrame.fromBuffer(new BufferVisitor(buf)))))
  })

  it('parse with parseFrame', function () {
    const error = new QuicError(1)
    const connectionCloseFrame = new ConnectionCloseFrame(error)

    strictEqual(connectionCloseFrame.type, 2)
    const buf = toBuffer(connectionCloseFrame)
    ok(buf.equals(bufferFromBytes([
      0x02,
      0x01, 0x00, 0x00, 0x00,
      0x28, 0x00,
      'Connection has reached an invalid state.',
    ])))
    ok(buf.equals(toBuffer(parseFrame(new BufferVisitor(buf), new PacketNumber(1)))))
  })
})
