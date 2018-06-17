'use strict'

// **Github:** https://github.com/fidm/quic
//
// **License:** MIT

import { suite, it } from 'tman'
import { ok, strictEqual } from 'assert'

import { bufferFromBytes } from '../common'
import { BufferVisitor, toBuffer } from '../../src/internal/common'
import { PacketNumber } from '../../src/internal/protocol'
import {
  parseFrame, PaddingFrame,
} from '../../src/internal/frame'

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
