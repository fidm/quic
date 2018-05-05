'use strict'

// **Github:** https://github.com/fidm/quic
//
// **License:** MIT

import { suite, it } from 'tman'
import { ok, strictEqual } from 'assert'

import { bufferFromBytes } from '../common'
import { BufferVisitor, toBuffer } from '../../src/internal/common'
import { QuicError } from '../../src/internal/error'
import { PacketNumber } from '../../src/internal/protocol'
import {
  parseFrame, ConnectionCloseFrame,
} from '../../src/internal/frame'

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
      0x00, 0x00, 0x00, 0x01,
      0x00, 0x28,
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
      0x00, 0x00, 0x00, 0x01,
      0x00, 0x28,
      'Connection has reached an invalid state.',
    ])))
    ok(buf.equals(toBuffer(parseFrame(new BufferVisitor(buf), new PacketNumber(1)))))
  })
})
