'use strict'

// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const tman = require('tman')
const assert = require('assert')
const QuicError = require('../lib/error')
const bufferFromBytes = require('./util').bufferFromBytes

tman.suite('error', function () {
  tman.it('new QuicError(0)', function () {
    let err = new QuicError(0)
    assert.strictEqual(err.code, 0)
    assert.strictEqual(err.name, 'NO_ERROR')
    assert.strictEqual(err.message, '')
    assert.ok(err.stack.includes('test/error.js'))
    assert.ok(err.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0])))
    assert.deepEqual(err, new QuicError('NO_ERROR'))
  })

  tman.it('new QuicError(1)', function () {
    let err = new QuicError(1)
    assert.strictEqual(err.code, 1)
    assert.strictEqual(err.name, 'INTERNAL_ERROR')
    assert.strictEqual(err.message, 'Connection has reached an invalid state.')
    assert.ok(err.stack.includes('test/error.js'))
    assert.ok(err.toBuffer().equals(bufferFromBytes([0x1, 0x0, 0x0, 0x0])))
    assert.deepEqual(err, new QuicError('INTERNAL_ERROR'))
  })

  tman.it('new QuicError(UNKNOWN_ERROR)', function () {
    let err = new QuicError('xxxxxxxx')
    assert.strictEqual(err.code, 0xffffffff)
    assert.strictEqual(err.name, 'UNKNOWN_ERROR')
    assert.strictEqual(err.message, 'xxxxxxxx')
    assert.ok(err.stack.includes('test/error.js'))
    assert.ok(err.toBuffer().equals(bufferFromBytes([0xff, 0xff, 0xff, 0xff])))
  })

  tman.it('QuicError.fromBuffer', function () {
    assert.strictEqual(QuicError.fromBuffer(bufferFromBytes([0x0, 0x0, 0x0, 0x0])), null)
    let err = QuicError.fromBuffer(bufferFromBytes([0x1, 0x0, 0x0, 0x0]))
    assert.deepEqual(err, new QuicError(1))

    err = QuicError.fromBuffer(bufferFromBytes([0x1, 0x1, 0x1, 0x1]))
    assert.strictEqual(err.code, 0xffffffff)
    assert.strictEqual(err.name, 'UNKNOWN_ERROR')
    assert.strictEqual(err.message, String(0x01010101))
  })
})
