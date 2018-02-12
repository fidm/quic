'use strict'

// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

import { join } from 'path'
import { suite, it } from 'tman'
import { ok, strictEqual, deepEqual } from 'assert'

import { QuicError } from '../src/internal/error'
import { Visitor, toBuffer } from '../src/internal/common'

import { bufferFromBytes } from './common'

suite('QUIC errors', function () {
  it('new QuicError(0)', function () {
    let err = new QuicError(0)
    strictEqual(err.code, 0)
    strictEqual(err.name, 'QUIC_NO_ERROR')
    strictEqual(err.message, '')
    ok(err.stack.includes(join('test', 'error.ts')))
    ok(toBuffer(err).equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0])))
    deepEqual(err, new QuicError('QUIC_NO_ERROR'))
  })

  it('new QuicError(1)', function () {
    let err = new QuicError(1)
    strictEqual(err.code, 1)
    strictEqual(err.name, 'QUIC_INTERNAL_ERROR')
    strictEqual(err.message, 'Connection has reached an invalid state.')
    ok(err.stack.includes(join('test', 'error.ts')))
    ok(toBuffer(err).equals(bufferFromBytes([0x1, 0x0, 0x0, 0x0])))
    deepEqual(err, new QuicError('QUIC_INTERNAL_ERROR'))
  })

  it('new QuicError(UNKNOWN_ERROR)', function () {
    let err = new QuicError('xxxxxxxx')
    strictEqual(err.code, 0xffffffff)
    strictEqual(err.name, 'INVALID_ERROR_CODE')
    strictEqual(err.message, 'xxxxxxxx')
    ok(err.stack.includes(join('test', 'error.ts')))
    ok(toBuffer(err).equals(bufferFromBytes([0xff, 0xff, 0xff, 0xff])))
  })

  it('QuicError.fromBuffer', function () {
    strictEqual(QuicError.fromBuffer(bufferFromBytes([0x0, 0x0, 0x0, 0x0])).name, 'QUIC_NO_ERROR')
    let err = QuicError.fromBuffer(bufferFromBytes([0x1, 0x0, 0x0, 0x0]))
    deepEqual(err, new QuicError(1))

    err = QuicError.fromBuffer(bufferFromBytes([0x1, 0x1, 0x1, 0x1]))
    strictEqual(err.code, 0xffffffff)
    strictEqual(err.name, 'INVALID_ERROR_CODE')
    strictEqual(err.message, String(0x01010101))
  })
})
