'use strict'

// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const tman = require('tman')
const assert = require('assert')
const QuicID = require('../lib/id')
const QuicFrame = require('../lib/frame')
const QuicError = require('../lib/error')
const bufferFromBytes = require('../lib/util').bufferFromBytes

tman.suite('QuicFrame', function () {
  tman.suite('PaddingFrame', function () {
    const PaddingFrame = QuicFrame.PaddingFrame

    tman.it('new PaddingFrame', function () {
      let paddingFrame = new PaddingFrame()

      assert.strictEqual(paddingFrame.flag, 0)
      assert.ok(paddingFrame.toBuffer().equals(bufferFromBytes([0x00])))
    })
  })

  tman.suite('ResetStreamFrame', function () {
    const ResetStreamFrame = QuicFrame.ResetStreamFrame

    tman.it('new ResetStreamFrame', function () {
      let streamId = QuicID.StreamId.fromId(1)
      let error = new QuicError(1)
      let offset = bufferFromBytes([0x01, 0x2, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
      let resetStreamFrame = new ResetStreamFrame(streamId, offset, error)

      assert.strictEqual(resetStreamFrame.flag, 1)
      assert.ok(resetStreamFrame.toBuffer().equals(bufferFromBytes([
        0x01,
        0x01, 0x00, 0x00, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x01, 0x00, 0x00, 0x00
      ])))
    })
  })
})
