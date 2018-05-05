'use strict'

// **Github:** https://github.com/fidm/quic
//
// **License:** MIT

import { suite, it } from 'tman'
import { ok, strictEqual } from 'assert'

import { bufferFromBytes } from '../common'
import { BufferVisitor, toBuffer } from '../../src/internal/common'
import { StreamID, PacketNumber } from '../../src/internal/protocol'
import {
  parseFrame, BlockedFrame,
} from '../../src/internal/frame'

suite('BLOCKED Frame', function () {
  it('new BlockedFrame with StreamID', function () {
    const streamID = new StreamID(10)
    const blockedFrame = new BlockedFrame(streamID)

    strictEqual(blockedFrame.type, 5)
    const buf = toBuffer(blockedFrame)
    ok(buf.equals(bufferFromBytes([
      0x05,
      0x00, 0x00, 0x00, 0x0a,
    ])))
    ok(buf.equals(toBuffer(BlockedFrame.fromBuffer(new BufferVisitor(buf)))))
  })

  it('parse with parseFrame', function () {
    const streamID = new StreamID(10)
    const blockedFrame = new BlockedFrame(streamID)

    strictEqual(blockedFrame.type, 5)
    const buf = toBuffer(blockedFrame)
    ok(buf.equals(bufferFromBytes([
      0x05,
      0x00, 0x00, 0x00, 0x0a,
    ])))
    ok(buf.equals(toBuffer(parseFrame(new BufferVisitor(buf), new PacketNumber(1)))))
  })
})
