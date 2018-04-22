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

suite('STREAM Frame', function () {
  it('new StreamFrame', function () {
    let streamID = new StreamID(1)
    let offset = new Offset(0)
    let data = bufferFromBytes(['abcdefg'])
    let streamFrame = new StreamFrame(streamID, offset, data, false)

    strictEqual(streamFrame.isFIN, false)
    let buf = toBuffer(streamFrame)
    ok(buf.equals(bufferFromBytes([
      0b10100000,
      0x1,
      0x7, 0x0,
      'abcdefg',
    ])))
    ok(buf.equals(toBuffer(StreamFrame.fromBuffer(buf))))

    streamID = streamID.nextID()
    offset = new Offset(offset.valueOf() + data.length)
    data = bufferFromBytes(['higklmn'])
    streamFrame = new StreamFrame(streamID, offset, data, false)

    strictEqual(streamFrame.isFIN, false)
    buf = toBuffer(streamFrame)
    ok(buf.equals(bufferFromBytes([
      0b10100100,
      0x3,
      0x7, 0x0,
      0x7, 0x0,
      'higklmn',
    ])))
    ok(buf.equals(toBuffer(StreamFrame.fromBuffer(buf))))

    streamID = streamID.nextID()
    offset = new Offset(offset.valueOf() + data.length)
    data = bufferFromBytes(['opqrst'])
    streamFrame = new StreamFrame(streamID, offset, data, false)

    strictEqual(streamFrame.isFIN, false)
    buf = toBuffer(streamFrame)
    ok(buf.equals(bufferFromBytes([
      0b10100100,
      0x5,
      0xe, 0x0,
      0x6, 0x0,
      'opqrst',
    ])))
    ok(buf.equals(toBuffer(StreamFrame.fromBuffer(buf))))

    streamID = streamID.nextID()
    offset = new Offset(offset.valueOf() + data.length)
    data = bufferFromBytes(['uvwxyz'])
    streamFrame = new StreamFrame(streamID, offset, data, true)

    strictEqual(streamFrame.isFIN, true)
    buf = toBuffer(streamFrame)
    ok(buf.equals(bufferFromBytes([
      0b11100100,
      0x7,
      0x14, 0x0,
      0x6, 0x0,
      'uvwxyz',
    ])))
    ok(buf.equals(toBuffer(StreamFrame.fromBuffer(buf))))
  })

  it('parse with parseFrame', function () {
    const streamID = new StreamID(1)
    const offset = new Offset(0)
    const data = bufferFromBytes(['abcd'])
    const streamFrame = new StreamFrame(streamID, offset, data, false)
    const buf = toBuffer(streamFrame)

    ok(buf.equals(toBuffer(parseFrame(buf, new PacketNumber(1)))))
  })

  it('when invalid StreamFrame type', function () {
    const streamID = new StreamID(1)
    const offset = new Offset(0)
    const data = bufferFromBytes(['abcd'])
    const streamFrame = new StreamFrame(streamID, offset, data, false)
    const buf = toBuffer(streamFrame)

    throws(() => StreamFrame.fromBuffer(Visitor.wrap(buf.slice(0, 1))), /INVALID_STREAM_DATA/)
    throws(() => StreamFrame.fromBuffer(Visitor.wrap(buf.slice(0, 2))), /INVALID_STREAM_DATA/)
    throws(() => StreamFrame.fromBuffer(Visitor.wrap(buf.slice(0, 3))), /INVALID_STREAM_DATA/)
    throws(() => StreamFrame.fromBuffer(Visitor.wrap(buf.slice(0, 4))), /INVALID_STREAM_DATA/)
    throws(() => StreamFrame.fromBuffer(Visitor.wrap(buf.slice(0, 5))), /INVALID_STREAM_DATA/)
    throws(() => StreamFrame.fromBuffer(Visitor.wrap(buf.slice(0, 6))), /INVALID_STREAM_DATA/)
    throws(() => StreamFrame.fromBuffer(Visitor.wrap(buf.slice(0, 7))), /INVALID_STREAM_DATA/)
    ok(buf.equals(toBuffer(StreamFrame.fromBuffer(Visitor.wrap(buf.slice(0, streamFrame.byteLen()))))))
  })
})
