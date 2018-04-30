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

suite('ACK Frame', function () {
  suite('parsing', function () {
    it('a sample ACK frame', function () {
      const buf = bufferFromBytes([0x40,
        0x1c,     // largest acked
        0x0, 0x0, // delay time
        0x1c, // block length
        0,
      ])
      const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
      ok(ackFrame.largestAcked === 0x1c)
      ok(ackFrame.lowestAcked === 0x1)
      ok(ackFrame.delayTime === 0)
      ok(ackFrame.hasMissingRanges() === false)

      // ignore Timestamps
      ok(toBuffer(ackFrame).equals(bufferFromBytes([0x40, 0x1c, 0x0, 0x0, 0x1c, 0x0])))
    })

    it('parse with parseFrame', function () {
      const buf = bufferFromBytes([0x40,
        0x1c,     // largest acked
        0x0, 0x0, // delay time
        0x1c, // block length
        0,
      ])
      const ackFrame = parseFrame(new BufferVisitor(buf), new PacketNumber(1)) as AckFrame
      ok(ackFrame.largestAcked === 0x1c)
      ok(ackFrame.lowestAcked === 0x1)
      ok(ackFrame.delayTime === 0)
      ok(ackFrame.hasMissingRanges() === false)

      // ignore Timestamps
      ok(toBuffer(ackFrame).equals(bufferFromBytes([0x40, 0x1c, 0x0, 0x0, 0x1c, 0x0])))
    })

    it('a frame without a timestamp', function () {
      const buf = bufferFromBytes([0x40, 0x3, 0x15, 0x50, 0x3, 0x0])
      const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf)) as AckFrame
      ok(ackFrame.largestAcked === 0x3)
      ok(ackFrame.lowestAcked === 0x1)
      ok(ackFrame.delayTime === 6816)
      ok(ackFrame.hasMissingRanges() === false)
    })

    it('a frame with a 48 bit packet number', function () {
      const buf = bufferFromBytes([0x4c, 0x37, 0x13, 0xad, 0xfb, 0xca, 0xde, 0x0, 0x0, 0x5, 0x1, 0, 0, 0, 0, 0])
      const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
      ok(ackFrame.largestAcked === 0x3713adfbcade)
      ok(ackFrame.lowestAcked === 0x3713adfbcade - 5 + 1)
      ok(ackFrame.hasMissingRanges() === false)
    })

    it('a frame with 1 ACKed packet', function () {
      const buf = bufferFromBytes([0x40, 0x10, 0x8e, 0x0, 0x1, 0x0])
      const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
      ok(ackFrame.largestAcked === 0x10)
      ok(ackFrame.lowestAcked === 0x10)
      ok(ackFrame.hasMissingRanges() === false)
    })

    it('a frame, when packet 1 was lost', function () {
      const buf = bufferFromBytes([0x40, 0x9, 0x92, 0x7, 0x8, 0x3, 0x2, 0x69, 0xa3, 0x0, 0x0, 0x1,
        0xc9, 0x2, 0x0, 0x46, 0x10])
      const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
      ok(ackFrame.largestAcked === 9)
      ok(ackFrame.lowestAcked === 2)
      ok(ackFrame.hasMissingRanges() === false)
    })

    it('a frame with multiple timestamps', function () {
      const buf = bufferFromBytes([0x40, 0x10, 0x0, 0x0, 0x10, 0x4, 0x1, 0x6b, 0x26, 0x4, 0x0, 0x3,
        0, 0, 0x2, 0, 0, 0x1, 0, 0])
      const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
      ok(ackFrame.largestAcked === 0x10)
      ok(ackFrame.lowestAcked === 1)
      ok(ackFrame.hasMissingRanges() === false)
    })

    it('errors when the ACK range is too large', function () {
      // LargestAcked: 0x1c
      // Length: 0x1d => LowestAcked would be -1
      throws(() => {
        const buf = bufferFromBytes([0x40, 0x1c, 0x8e, 0x0, 0x1d, 0x1, 0x1, 0x6b, 0x26, 0x3, 0x0])
        AckFrame.fromBuffer(new BufferVisitor(buf))
      })
    })

    it('errors when the first ACK range is empty', function () {
      throws(() => {
        const buf = bufferFromBytes([0x40, 0x9, 0x8e, 0x0, 0x0, 0x1, 0])
        AckFrame.fromBuffer(new BufferVisitor(buf))
      })
    })
  })

  suite('ACK blocks', function () {
    it('a frame with one ACK block', function () {
      const buf = bufferFromBytes([0x60, 0x18, 0x94, 0x1, 0x1, 0x3, 0x2, 0x10, 0x2, 0x1, 0x5c, 0xd5,
        0x0, 0x0, 0x0, 0x95, 0x0])
      const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
      ok(ackFrame.largestAcked === 0x18)
      ok(ackFrame.lowestAcked === 0x4)
      strictEqual(ackFrame.hasMissingRanges(), true)
      strictEqual(ackFrame.ackRanges.length, 2)
      deepEqual(ackFrame.ackRanges[0], new AckRange(22, 24))
      deepEqual(ackFrame.ackRanges[1], new AckRange(4, 19))
    })

    it('rejects a frame that says it has ACK blocks in the typeByte, but doesn\'t have any', function () {
      const buf = bufferFromBytes([0x63, 0x4, 0xff, 0xff, 0, 2, 0, 0, 0, 0, 0, 0])
      throws(() => AckFrame.fromBuffer(new BufferVisitor(buf)))
    })

    it('rejects a frame with invalid ACK ranges', function () {
      // like the test before, but increased the last ACK range, such that the FirstPacketNumber would be negative
      const buf = bufferFromBytes([0x60, 0x18, 0x94, 0x1, 0x1, 0x3, 0x2, 0x15, 0x2, 0x1, 0x5c, 0xd5, 0x0,
        0x0, 0x0, 0x95, 0x0])
      throws(() => AckFrame.fromBuffer(new BufferVisitor(buf)))
    })

    it('a frame with multiple single packets missing', function () {
      const buf = bufferFromBytes([0x60, 0x27, 0xda, 0x0, 0x6, 0x9, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
        0x1, 0x1, 0x1, 0x1, 0x13, 0x2, 0x1, 0x71, 0x12, 0x3, 0x0, 0x0, 0x47, 0x2])
      const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
      ok(ackFrame.largestAcked === 0x27)
      ok(ackFrame.lowestAcked === 0x1)
      strictEqual(ackFrame.hasMissingRanges(), true)
      strictEqual(ackFrame.ackRanges.length, 7)
      deepEqual(ackFrame.ackRanges[0], new AckRange(31, 39))
      deepEqual(ackFrame.ackRanges[1], new AckRange(29, 29))
      deepEqual(ackFrame.ackRanges[2], new AckRange(27, 27))
      deepEqual(ackFrame.ackRanges[3], new AckRange(25, 25))
      deepEqual(ackFrame.ackRanges[4], new AckRange(23, 23))
      deepEqual(ackFrame.ackRanges[5], new AckRange(21, 21))
      deepEqual(ackFrame.ackRanges[6], new AckRange(1, 19))
    })

    it('a frame with packet 1 and one more packet lost', function () {
      const buf = bufferFromBytes([0x60, 0xc, 0x92, 0x0, 0x1, 0x1, 0x1, 0x9, 0x2, 0x2, 0x53, 0x43,
        0x1, 0x0, 0x0, 0xa7, 0x0])
      const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
      ok(ackFrame.largestAcked === 12)
      ok(ackFrame.lowestAcked === 2)
      strictEqual(ackFrame.hasMissingRanges(), true)
      strictEqual(ackFrame.ackRanges.length, 2)
      deepEqual(ackFrame.ackRanges[0], new AckRange(12, 12))
      deepEqual(ackFrame.ackRanges[1], new AckRange(2, 10))
    })

    it('a frame with multiple longer ACK blocks', function () {
      const buf = bufferFromBytes([0x60, 0x52, 0xd1, 0x0, 0x3, 0x17, 0xa, 0x10, 0x4, 0x8, 0x2, 0x12,
        0x2, 0x1, 0x6c, 0xc8, 0x2, 0x0, 0x0, 0x7e, 0x1])
      const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
      ok(ackFrame.largestAcked === 0x52)
      ok(ackFrame.lowestAcked === 2)
      strictEqual(ackFrame.hasMissingRanges(), true)
      strictEqual(ackFrame.ackRanges.length, 4)
      deepEqual(ackFrame.ackRanges[0], new AckRange(60, 0x52))
      deepEqual(ackFrame.ackRanges[1], new AckRange(34, 49))
      deepEqual(ackFrame.ackRanges[2], new AckRange(22, 29))
      deepEqual(ackFrame.ackRanges[3], new AckRange(2, 19))
    })

    suite('more than 256 lost packets in a row', function () {
      // 255 missing packets fit into a single ACK block
      it('a frame with a range of 255 missing packets', function () {
        const buf = bufferFromBytes([0x60 ^ 0x4,
          0x1, 0x15, // largest acked
          0x0, 0x0, // delay time
          0x1,        // num ACK blocks
          0x3,        // 1st block
          0xff, 0x13, // 2nd block
          0,
        ])
        const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
        ok(ackFrame.largestAcked === 0x115)
        ok(ackFrame.lowestAcked === 1)
        strictEqual(ackFrame.hasMissingRanges(), true)
        strictEqual(ackFrame.ackRanges.length, 2)
        deepEqual(ackFrame.ackRanges[0], new AckRange(20 + 255, 0x115))
        deepEqual(ackFrame.ackRanges[1], new AckRange(1, 19))
      })

      // 256 missing packets fit into two ACK blocks
      it('a frame with a range of 256 missing packets', function () {
        const buf = bufferFromBytes([0x60 ^ 0x4,
          0x1, 0x14, // largest acked
          0x0, 0x0, // delay time
          0x2,       // num ACK blocks
          0x1,       // 1st block
          0xff, 0x0, // 2nd block
          0x1, 0x13, // 3rd block
          0,
        ])
        const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
        ok(ackFrame.largestAcked === 0x114)
        ok(ackFrame.lowestAcked === 1)
        strictEqual(ackFrame.hasMissingRanges(), true)
        strictEqual(ackFrame.ackRanges.length, 2)
        deepEqual(ackFrame.ackRanges[0], new AckRange(20 + 256, 0x114))
        deepEqual(ackFrame.ackRanges[1], new AckRange(1, 19))
      })

      it('a frame with an incomplete range at the end', function () {
        // this is a modified ACK frame that has 5 instead of originally 6 written ranges
        // each gap is 300 packets and thus takes 2 ranges
        // the last range is incomplete, and should be completely ignored
        const buf = bufferFromBytes([0x60 ^ 0x4,
          0x3, 0x9b, // largest acked
          0x0, 0x0, // delay time
          0x5,       // num ACK blocks, instead of 0x6
          0x1,       // 1st block
          0xff, 0x0, // 2nd block
          0x2d, 0x1, // 3rd block
          0xff, 0x0, // 4th block
          0x2d, 0x1, // 5th block
          0xff, 0x0, /*0x2d, 0x14,*/ // 6th block
          0,
        ])
        const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
        ok(ackFrame.largestAcked === 0x39b)
        ok(ackFrame.lowestAcked === 0x141)
        strictEqual(ackFrame.hasMissingRanges(), true)
        strictEqual(ackFrame.ackRanges.length, 3)
        deepEqual(ackFrame.ackRanges[0], new AckRange(20 + 3 * 301, 20 + 3 * 301))
        deepEqual(ackFrame.ackRanges[1], new AckRange(20 + 2 * 301, 20 + 2 * 301))
        deepEqual(ackFrame.ackRanges[2], new AckRange(20 + 1 * 301, 20 + 1 * 301))
      })

      it('a frame with one long range, spanning 2 blocks, of missing packets', function () { // 280 missing packets
        const buf = bufferFromBytes([0x60 ^ 0x4,
          0x1, 0x44, // largest acked
          0x0, 0x0, // delay time
          0x2,       // num ACK blocks
          0x19,      // 1st block
          0xff, 0x0, // 2nd block
          0x19, 0x13, // 3rd block
          0,
        ])
        const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
        ok(ackFrame.largestAcked === 0x144)
        ok(ackFrame.lowestAcked === 1)
        strictEqual(ackFrame.hasMissingRanges(), true)
        strictEqual(ackFrame.ackRanges.length, 2)
        deepEqual(ackFrame.ackRanges[0], new AckRange(300, 0x144))
        deepEqual(ackFrame.ackRanges[1], new AckRange(1, 19))
      })

      it('a frame with one long range, spanning multiple blocks, of missing packets', function () {
        // 2345 missing packets
        const buf = bufferFromBytes([0x60 ^ 0x4,
          0x9, 0x5b, // largest acked
          0x0, 0x0, // delay time
          0xa,       // num ACK blocks
          0x1f,      // 1st block
          0xff, 0x0, // 2nd block
          0xff, 0x0, // 3rd block
          0xff, 0x0, // 4th block
          0xff, 0x0, // 5th block
          0xff, 0x0, // 6th block
          0xff, 0x0, // 7th block
          0xff, 0x0, // 8th block
          0xff, 0x0, // 9th block
          0xff, 0x0, // 10th block
          0x32, 0x13, // 11th block
          0,
        ])
        const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
        ok(ackFrame.largestAcked === 0x95b)
        ok(ackFrame.lowestAcked === 1)
        strictEqual(ackFrame.hasMissingRanges(), true)
        strictEqual(ackFrame.ackRanges.length, 2)
        deepEqual(ackFrame.ackRanges[0], new AckRange(2365, 0x95b))
        deepEqual(ackFrame.ackRanges[1], new AckRange(1, 19))
      })

      it.skip('a frame with multiple long ranges of missing packets', function () {
        const buf = bufferFromBytes([0x60 ^ 0x4 ^ 0x1,
          0x9, 0x66, // largest acked
          0x0, 0x0, // delay time
          0x7,      // num ACK blocks
          0x0, 0x7, // 1st block
          0xff, 0x0, 0x0, // 2nd block
          0xf5, 0x2, 0x8a, // 3rd block
          0xc8, 0x0, 0xe6, // 4th block
          0xff, 0x0, 0x0, // 5th block
          0xff, 0x0, 0x0, // 6th block
          0xff, 0x0, 0x0, // 7th block
          0x23, 0x0, 0x13, // 8th block
          0,
        ])
        const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
        ok(ackFrame.largestAcked === 0x966)
        ok(ackFrame.lowestAcked === 1)
        strictEqual(ackFrame.hasMissingRanges(), true)
        strictEqual(ackFrame.ackRanges.length, 4)
        deepEqual(ackFrame.ackRanges[0], new AckRange(2400, 0x966))
        deepEqual(ackFrame.ackRanges[1], new AckRange(1250, 1899))
        deepEqual(ackFrame.ackRanges[2], new AckRange(820, 1049))
        deepEqual(ackFrame.ackRanges[3], new AckRange(1, 19))
      })
    })
  })

  it('errors on EOFs', function () {
    const buf = bufferFromBytes([0x60 ^ 0x4 ^ 0x1,
      0x9, 0x66, // largest acked
      0x23, 0x1, // delay time
      0x7,      // num ACk blocks
      0x0, 0x7, // 1st block
      0xff, 0x0, 0x0, // 2nd block
      0xf5, 0x2, 0x8a, // 3rd block
      0xc8, 0x0, 0xe6, // 4th block
      0xff, 0x0, 0x0, // 5th block
      0xff, 0x0, 0x0, // 6th block
      0xff, 0x0, 0x0, // 7th block
      0x23, 0x0, 0x13, // 8th blocks
      0x2,                       // num timestamps
      0x1, 0x13, 0xae, 0xb, 0x0, // 1st timestamp
      0x0, 0x80, 0x5, // 2nd timestamp
    ])
    AckFrame.fromBuffer(new BufferVisitor(buf))
    for (let i = 0; i < buf.length; i++) {
      throws(() => AckFrame.fromBuffer(new BufferVisitor(buf.slice(0, i))))
    }
  })

  suite('when toBuffer', function () {
    suite('self-consistency', function () {
      it('a simple ACK frame', function () {
        const frame = new AckFrame()
        frame.largestAcked = 1
        frame.lowestAcked = 1
        const buf = toBuffer(frame)
        const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
        ok(ackFrame.largestAcked === 1)
        ok(ackFrame.lowestAcked === 1)
        strictEqual(ackFrame.hasMissingRanges(), false)
      })

      it('the correct block length in a simple ACK frame', function () {
        const frame = new AckFrame()
        frame.largestAcked = 20
        frame.lowestAcked = 10
        const buf = toBuffer(frame)
        const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
        ok(ackFrame.largestAcked === 20)
        ok(ackFrame.lowestAcked === 10)
        strictEqual(ackFrame.hasMissingRanges(), false)
      })

      it('a simple ACK frame with a high packet number', function () {
        const frame = new AckFrame()
        frame.largestAcked = 0xDEADBEEFCAFE
        frame.lowestAcked = 0xDEADBEEFCAFE
        const buf = toBuffer(frame)
        const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
        ok(ackFrame.largestAcked === 0xDEADBEEFCAFE)
        ok(ackFrame.lowestAcked === 0xDEADBEEFCAFE)
        strictEqual(ackFrame.hasMissingRanges(), false)
      })

      it('an ACK frame with one packet missing', function () {
        const frame = new AckFrame()
        frame.largestAcked = 40
        frame.lowestAcked = 1
        frame.ackRanges.push(new AckRange(25, 40), new AckRange(1, 23))
        const buf = toBuffer(frame)
        const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
        ok(ackFrame.largestAcked === 40)
        ok(ackFrame.lowestAcked === 1)
        strictEqual(ackFrame.hasMissingRanges(), true)
        strictEqual(ackFrame.ackRanges.length, 2)
        deepEqual(ackFrame.ackRanges[0], new AckRange(25, 40))
        deepEqual(ackFrame.ackRanges[1], new AckRange(1, 23))
      })

      it('an ACK frame with multiple missing packets', function () {
        const frame = new AckFrame()
        frame.largestAcked = 25
        frame.lowestAcked = 1
        frame.ackRanges.push(
          new AckRange(22, 25),
          new AckRange(15, 18),
          new AckRange(13, 13),
          new AckRange(1, 10),
        )
        const buf = toBuffer(frame)
        const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
        ok(ackFrame.largestAcked === 25)
        ok(ackFrame.lowestAcked === 1)
        strictEqual(ackFrame.hasMissingRanges(), true)
        strictEqual(ackFrame.ackRanges.length, 4)
        deepEqual(ackFrame.ackRanges[0], new AckRange(22, 25))
        deepEqual(ackFrame.ackRanges[1], new AckRange(15, 18))
        deepEqual(ackFrame.ackRanges[2], new AckRange(13, 13))
        deepEqual(ackFrame.ackRanges[3], new AckRange(1, 10))
      })

      it('rejects a frame with incorrect LargestObserved value', function () {
        const frame = new AckFrame()
        frame.largestAcked = 26
        frame.lowestAcked = 1
        frame.ackRanges.push(
          new AckRange(12, 25),
          new AckRange(1, 10),
        )
        throws(() => toBuffer(frame))
      })

      it('rejects a frame with incorrect LargestObserved value 2', function () {
        const frame = new AckFrame()
        frame.largestAcked = 25
        frame.lowestAcked = 2
        frame.ackRanges.push(
          new AckRange(12, 25),
          new AckRange(1, 10),
        )
        throws(() => toBuffer(frame))
      })

      suite('longer gaps between ACK blocks', function () {
        it('only one block for 254 lost packets', function () {
          const frame = new AckFrame()
          frame.largestAcked = 300
          frame.lowestAcked = 1
          frame.ackRanges.push(
            new AckRange(20 + 254, 300),
            new AckRange(1, 19),
          )
          strictEqual(frame.numWritableNackRanges(), 2)

          const buf = toBuffer(frame)
          const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
          ok(ackFrame.largestAcked === 300)
          ok(ackFrame.lowestAcked === 1)
          strictEqual(ackFrame.hasMissingRanges(), true)
          strictEqual(ackFrame.ackRanges.length, 2)
          deepEqual(ackFrame.ackRanges[0], new AckRange(20 + 254, 300))
          deepEqual(ackFrame.ackRanges[1], new AckRange(1, 19))
        })

        it('only one block for 255 lost packets', function () {
          const frame = new AckFrame()
          frame.largestAcked = 300
          frame.lowestAcked = 1
          frame.ackRanges.push(
            new AckRange(20 + 255, 300),
            new AckRange(1, 19),
          )
          strictEqual(frame.numWritableNackRanges(), 2)

          const buf = toBuffer(frame)
          const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
          ok(ackFrame.largestAcked === 300)
          ok(ackFrame.lowestAcked === 1)
          strictEqual(ackFrame.hasMissingRanges(), true)
          strictEqual(ackFrame.ackRanges.length, 2)
          deepEqual(ackFrame.ackRanges[0], new AckRange(20 + 255, 300))
          deepEqual(ackFrame.ackRanges[1], new AckRange(1, 19))
        })

        it('two block for 256 lost packets', function () {
          const frame = new AckFrame()
          frame.largestAcked = 300
          frame.lowestAcked = 1
          frame.ackRanges.push(
            new AckRange(20 + 256, 300),
            new AckRange(1, 19),
          )
          strictEqual(frame.numWritableNackRanges(), 3)

          const buf = toBuffer(frame)
          const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
          ok(ackFrame.largestAcked === 300)
          ok(ackFrame.lowestAcked === 1)
          strictEqual(ackFrame.hasMissingRanges(), true)
          strictEqual(ackFrame.ackRanges.length, 2)
          deepEqual(ackFrame.ackRanges[0], new AckRange(20 + 256, 300))
          deepEqual(ackFrame.ackRanges[1], new AckRange(1, 19))
        })

        it('two block for 510 lost packets', function () {
          const frame = new AckFrame()
          frame.largestAcked = 600
          frame.lowestAcked = 1
          frame.ackRanges.push(
            new AckRange(20 + 510, 600),
            new AckRange(1, 19),
          )
          strictEqual(frame.numWritableNackRanges(), 3)

          const buf = toBuffer(frame)
          const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
          ok(ackFrame.largestAcked === 600)
          ok(ackFrame.lowestAcked === 1)
          strictEqual(ackFrame.hasMissingRanges(), true)
          strictEqual(ackFrame.ackRanges.length, 2)
          deepEqual(ackFrame.ackRanges[0], new AckRange(20 + 510, 600))
          deepEqual(ackFrame.ackRanges[1], new AckRange(1, 19))
        })

        it('two block for 511 lost packets', function () {
          const frame = new AckFrame()
          frame.largestAcked = 600
          frame.lowestAcked = 1
          frame.ackRanges.push(
            new AckRange(20 + 511, 600),
            new AckRange(1, 19),
          )
          strictEqual(frame.numWritableNackRanges(), 4)

          const buf = toBuffer(frame)
          const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
          ok(ackFrame.largestAcked === 600)
          ok(ackFrame.lowestAcked === 1)
          strictEqual(ackFrame.hasMissingRanges(), true)
          strictEqual(ackFrame.ackRanges.length, 2)
          deepEqual(ackFrame.ackRanges[0], new AckRange(20 + 511, 600))
          deepEqual(ackFrame.ackRanges[1], new AckRange(1, 19))
        })

        it('two block for 512 lost packets', function () {
          const frame = new AckFrame()
          frame.largestAcked = 600
          frame.lowestAcked = 1
          frame.ackRanges.push(
            new AckRange(20 + 512, 600),
            new AckRange(1, 19),
          )
          strictEqual(frame.numWritableNackRanges(), 4)

          const buf = toBuffer(frame)
          const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
          ok(ackFrame.largestAcked === 600)
          ok(ackFrame.lowestAcked === 1)
          strictEqual(ackFrame.hasMissingRanges(), true)
          strictEqual(ackFrame.ackRanges.length, 2)
          deepEqual(ackFrame.ackRanges[0], new AckRange(20 + 512, 600))
          deepEqual(ackFrame.ackRanges[1], new AckRange(1, 19))
        })

        it('multiple blocks for a lot of lost packets', function () {
          const frame = new AckFrame()
          frame.largestAcked = 3000
          frame.lowestAcked = 1
          frame.ackRanges.push(
            new AckRange(2900, 3000),
            new AckRange(1, 19),
          )

          const buf = toBuffer(frame)
          const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
          ok(ackFrame.largestAcked === 3000)
          ok(ackFrame.lowestAcked === 1)
          strictEqual(ackFrame.hasMissingRanges(), true)
          strictEqual(ackFrame.ackRanges.length, 2)
          deepEqual(ackFrame.ackRanges[0], new AckRange(2900, 3000))
          deepEqual(ackFrame.ackRanges[1], new AckRange(1, 19))
        })

        it('multiple longer blocks for 256 lost packets', function () {
          const frame = new AckFrame()
          frame.largestAcked = 3600
          frame.lowestAcked = 1
          frame.ackRanges.push(
            new AckRange(2900, 3600),
            new AckRange(1000, 2500),
            new AckRange(1, 19),
          )

          const buf = toBuffer(frame)
          const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
          ok(ackFrame.largestAcked === 3600)
          ok(ackFrame.lowestAcked === 1)
          strictEqual(ackFrame.hasMissingRanges(), true)
          strictEqual(ackFrame.ackRanges.length, 3)
          deepEqual(ackFrame.ackRanges[0], new AckRange(2900, 3600))
          deepEqual(ackFrame.ackRanges[1], new AckRange(1000, 2500))
          deepEqual(ackFrame.ackRanges[2], new AckRange(1, 19))
        })
      })

      suite('longer ACK blocks', function () {
        it('a 1 byte Missing Sequence Number Delta', function () {
          const frame = new AckFrame()
          frame.largestAcked = 200
          frame.lowestAcked = 1

          const buf = toBuffer(frame)
          strictEqual(buf[0] & 0x3, 0x0)
          const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
          ok(ackFrame.largestAcked === 200)
          ok(ackFrame.lowestAcked === 1)
        })

        it('a 2 byte Missing Sequence Number Delta', function () {
          const frame = new AckFrame()
          frame.largestAcked = 0x100
          frame.lowestAcked = 1

          const buf = toBuffer(frame)
          strictEqual(buf[0] & 0x3, 0x1)
          const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
          ok(ackFrame.largestAcked === 0x100)
          ok(ackFrame.lowestAcked === 1)
        })

        it('a 4 byte Missing Sequence Number Delta', function () {
          const frame = new AckFrame()
          frame.largestAcked = 0x10000
          frame.lowestAcked = 1

          const buf = toBuffer(frame)
          strictEqual(buf[0] & 0x3, 0x2)
          const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
          ok(ackFrame.largestAcked === 0x10000)
          ok(ackFrame.lowestAcked === 1)
        })

        it('a 6 byte Missing Sequence Number Delta', function () {
          const frame = new AckFrame()
          frame.largestAcked = 0x100000000
          frame.lowestAcked = 1

          const buf = toBuffer(frame)
          strictEqual(buf[0] & 0x3, 0x3)
          const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
          ok(ackFrame.largestAcked === 0x100000000)
          ok(ackFrame.lowestAcked === 1)
        })

        it('a 1 byte Missing Sequence Number Delta, if all ACK blocks are short', function () {
          const frame = new AckFrame()
          frame.largestAcked = 5001
          frame.lowestAcked = 1
          frame.ackRanges.push(
            new AckRange(5000, 5001),
            new AckRange(250, 300),
            new AckRange(1, 200),
          )

          const buf = toBuffer(frame)
          strictEqual(buf[0] & 0x3, 0x0)
          const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
          ok(ackFrame.largestAcked === 5001)
          ok(ackFrame.lowestAcked === 1)
          strictEqual(ackFrame.hasMissingRanges(), true)
          strictEqual(ackFrame.ackRanges.length, 3)
          deepEqual(ackFrame.ackRanges[0], new AckRange(5000, 5001))
          deepEqual(ackFrame.ackRanges[1], new AckRange(250, 300))
          deepEqual(ackFrame.ackRanges[2], new AckRange(1, 200))
        })

        it('a 2 byte Missing Sequence Number Delta, for a frame with 2 ACK ranges', function () {
          const frame = new AckFrame()
          frame.largestAcked = 10000
          frame.lowestAcked = 1
          frame.ackRanges.push(
            new AckRange(9990, 10000),
            new AckRange(1, 256),
          )

          const buf = toBuffer(frame)
          strictEqual(buf[0] & 0x3, 0x1)
          const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
          ok(ackFrame.largestAcked === 10000)
          ok(ackFrame.lowestAcked === 1)
          strictEqual(ackFrame.hasMissingRanges(), true)
          strictEqual(ackFrame.ackRanges.length, 2)
          deepEqual(ackFrame.ackRanges[0], new AckRange(9990, 10000))
          deepEqual(ackFrame.ackRanges[1], new AckRange(1, 256))
        })
      })

      suite('too many ACK blocks', function () {
        it('skips the lowest ACK ranges, if there are more than 255 AckRanges', function () {
          const ackRanges = new Array(300)
          for (let i = 1; i <= 300; i++) {
            ackRanges[300 - i] = new AckRange(3 * i, 3 * i + 1)
          }
          const frame = new AckFrame()
          frame.largestAcked = ackRanges[0].last
          frame.lowestAcked = ackRanges[ackRanges.length - 1].first
          frame.ackRanges = ackRanges

          const buf = toBuffer(frame)
          const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
          ok(ackFrame.largestAcked === frame.largestAcked)
          ok(ackFrame.lowestAcked === ackRanges[254].first)
          strictEqual(ackFrame.ackRanges.length, 0xff)
          strictEqual(ackFrame.validateAckRanges(), true)
        })

        it('skips the lowest ACK ranges, if the gaps are large', function () {
          const ackRanges = new Array(100)
          // every AckRange will take 4 written ACK ranges
          for (let i = 1; i <= 100; i++) {
            ackRanges[100 - i] = new AckRange(1000 * i, 1000 * i + 1)
          }
          const frame = new AckFrame()
          frame.largestAcked = ackRanges[0].last
          frame.lowestAcked = ackRanges[ackRanges.length - 1].first
          frame.ackRanges = ackRanges

          const buf = toBuffer(frame)
          const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
          ok(ackFrame.largestAcked === frame.largestAcked)
          ok(ackFrame.lowestAcked === ackRanges[ackFrame.ackRanges.length - 1].first)
          strictEqual(ackFrame.ackRanges.length, 256 / 4)
          strictEqual(ackFrame.validateAckRanges(), true)
        })

        it('works with huge gaps', function () {
          const ackRanges = [
            new AckRange(2 * 255 * 200, 2 * 255 * 200 + 1),
            new AckRange(1 * 255 * 200, 1 * 255 * 200 + 1),
            new AckRange(1, 2),
          ]
          const frame = new AckFrame()
          frame.largestAcked = ackRanges[0].last
          frame.lowestAcked = ackRanges[ackRanges.length - 1].first
          frame.ackRanges = ackRanges

          const buf = toBuffer(frame)
          const ackFrame = AckFrame.fromBuffer(new BufferVisitor(buf))
          ok(ackFrame.largestAcked === frame.largestAcked)
          ok(ackFrame.lowestAcked === ackRanges[ackFrame.ackRanges.length - 1].first)
          strictEqual(ackFrame.ackRanges.length, 2)
          strictEqual(ackFrame.validateAckRanges(), true)
        })
      })
    })
  })

  suite('ACK range validator', function () {
    it('accepts an ACK without NACK Ranges', function () {
      const frame = new AckFrame()
      frame.largestAcked = 7
      strictEqual(frame.validateAckRanges(), true)
    })

    it('rejects ACK ranges with a single range', function () {
      const frame = new AckFrame()
      frame.largestAcked = 10
      frame.ackRanges.push(new AckRange(1, 10))
      strictEqual(frame.validateAckRanges(), false)
    })

    it('rejects ACK ranges with LastPacketNumber of the first range unequal to LargestObserved', function () {
      const frame = new AckFrame()
      frame.largestAcked = 10
      frame.ackRanges.push(
        new AckRange(8, 9),
        new AckRange(2, 3),
      )
      strictEqual(frame.validateAckRanges(), false)
    })

    it('rejects ACK ranges with FirstPacketNumber greater than LastPacketNumber', function () {
      const frame = new AckFrame()
      frame.largestAcked = 10
      frame.ackRanges.push(
        new AckRange(8, 10),
        new AckRange(4, 3),
      )
      strictEqual(frame.validateAckRanges(), false)
    })

    it('rejects ACK ranges with FirstPacketNumber greater than LargestObserved', function () {
      const frame = new AckFrame()
      frame.largestAcked = 5
      frame.ackRanges.push(
        new AckRange(4, 10),
        new AckRange(1, 2),
      )
      strictEqual(frame.validateAckRanges(), false)
    })

    it('rejects ACK ranges in the wrong order', function () {
      const frame = new AckFrame()
      frame.largestAcked = 7
      frame.ackRanges.push(
        new AckRange(2, 2),
        new AckRange(6, 7),
      )
      strictEqual(frame.validateAckRanges(), false)
    })

    it('rejects with overlapping ACK ranges', function () {
      const frame = new AckFrame()
      frame.largestAcked = 7
      frame.ackRanges.push(
        new AckRange(5, 7),
        new AckRange(2, 5),
      )
      strictEqual(frame.validateAckRanges(), false)
    })

    it('rejects ACK ranges that are part of a larger ACK range', function () {
      const frame = new AckFrame()
      frame.largestAcked = 7
      frame.ackRanges.push(
        new AckRange(4, 7),
        new AckRange(5, 6),
      )
      strictEqual(frame.validateAckRanges(), false)
    })

    it('rejects with directly adjacent ACK ranges', function () {
      const frame = new AckFrame()
      frame.largestAcked = 7
      frame.ackRanges.push(
        new AckRange(5, 7),
        new AckRange(2, 4),
      )
      strictEqual(frame.validateAckRanges(), false)
    })

    it('accepts an ACK with one lost packet', function () {
      const frame = new AckFrame()
      frame.largestAcked = 10
      frame.ackRanges.push(
        new AckRange(5, 10),
        new AckRange(1, 3),
      )
      strictEqual(frame.validateAckRanges(), true)
    })

    it('accepts an ACK with multiple lost packets', function () {
      const frame = new AckFrame()
      frame.largestAcked = 20
      frame.ackRanges.push(
        new AckRange(15, 20),
        new AckRange(10, 12),
        new AckRange(1, 3),
      )
      strictEqual(frame.validateAckRanges(), true)
    })
  })

  suite('check if ACK frame acks a certain packet', function () {
    it('works with an ACK without any ranges', function () {
      const frame = new AckFrame()
      frame.largestAcked = 10
      frame.lowestAcked = 5
      strictEqual(frame.acksPacket(1), false)
      strictEqual(frame.acksPacket(4), false)
      strictEqual(frame.acksPacket(5), true)
      strictEqual(frame.acksPacket(8), true)
      strictEqual(frame.acksPacket(10), true)
      strictEqual(frame.acksPacket(11), false)
      strictEqual(frame.acksPacket(20), false)
    })

    it('works with an ACK with multiple ACK ranges', function () {
      const frame = new AckFrame()
      frame.largestAcked = 20
      frame.lowestAcked = 5
      frame.ackRanges.push(
        new AckRange(15, 20),
        new AckRange(5, 8),
      )
      strictEqual(frame.acksPacket(4), false)
      strictEqual(frame.acksPacket(5), true)
      strictEqual(frame.acksPacket(7), true)
      strictEqual(frame.acksPacket(8), true)
      strictEqual(frame.acksPacket(9), false)
      strictEqual(frame.acksPacket(14), false)
      strictEqual(frame.acksPacket(15), true)
      strictEqual(frame.acksPacket(18), true)
      strictEqual(frame.acksPacket(20), true)
      strictEqual(frame.acksPacket(21), false)
    })
  })
})
