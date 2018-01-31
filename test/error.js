'use strict'

// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const path = require('path')
const { suite, it } = require('tman')
const { ok, strictEqual, deepEqual } = require('assert')

const { QuicError } = require('../lib/internal/error')

const { bufferFromBytes } = require('./common')

suite('QUIC errors', function () {
  it('new QuicError(0)', function () {
    let err = new QuicError(0)
    strictEqual(err.code, 0)
    strictEqual(err.name, 'QUIC_NO_ERROR')
    strictEqual(err.message, '')
    ok(err.stack.includes(path.join('test', 'error.js')))
    ok(err.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0])))
    deepEqual(err, new QuicError('QUIC_NO_ERROR'))
  })

  it('new QuicError(1)', function () {
    let err = new QuicError(1)
    strictEqual(err.code, 1)
    strictEqual(err.name, 'QUIC_INTERNAL_ERROR')
    strictEqual(err.message, 'Connection has reached an invalid state.')
    ok(err.stack.includes(path.join('test', 'error.js')))
    ok(err.toBuffer().equals(bufferFromBytes([0x1, 0x0, 0x0, 0x0])))
    deepEqual(err, new QuicError('QUIC_INTERNAL_ERROR'))
  })

  it('new QuicError(UNKNOWN_ERROR)', function () {
    let err = new QuicError('xxxxxxxx')
    strictEqual(err.code, 0xffffffff)
    strictEqual(err.name, 'INVALID_ERROR_CODE')
    strictEqual(err.message, 'xxxxxxxx')
    ok(err.stack.includes(path.join('test', 'error.js')))
    ok(err.toBuffer().equals(bufferFromBytes([0xff, 0xff, 0xff, 0xff])))
  })

  it('QuicError.fromBuffer', function () {
    strictEqual(QuicError.fromBuffer(bufferFromBytes([0x0, 0x0, 0x0, 0x0])), null)
    let err = QuicError.fromBuffer(bufferFromBytes([0x1, 0x0, 0x0, 0x0]))
    deepEqual(err, new QuicError(1))

    err = QuicError.fromBuffer(bufferFromBytes([0x1, 0x1, 0x1, 0x1]))
    strictEqual(err.code, 0xffffffff)
    strictEqual(err.name, 'INVALID_ERROR_CODE')
    strictEqual(err.message, String(0x01010101))
  })
})
