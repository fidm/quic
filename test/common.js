'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const { suite, it } = require('tman')
const { ok, strictEqual } = require('assert')

const { Visitor, Float16MaxValue, readUFloat16, writeUFloat16 } = require('../lib/internal/common')

exports.bufferFromBytes = bufferFromBytes
function bufferFromBytes (array) {
  let bytes = []
  if (!Array.isArray(array)) array = [array]
  for (let val of array) {
    if (typeof val !== 'string') bytes.push(val)
    else {
      for (let byte of Buffer.from(val, 'utf8').values()) bytes.push(byte)
    }
  }
  return Buffer.from(bytes)
}

suite('common', function () {
  it('bufferFromBytes', function () {
    ok(bufferFromBytes(0xff).equals(Buffer.from([0xff])))
    ok(bufferFromBytes([0xff]).equals(Buffer.from([0xff])))
    ok(bufferFromBytes([0xff, 0x00]).equals(Buffer.from([0xff, 0x00])))
    ok(bufferFromBytes(['a', 'b']).equals(Buffer.from([0x61, 0x62])))
    ok(bufferFromBytes(['ab', 'c', 0x64]).equals(Buffer.from([0x61, 0x62, 0x63, 0x64])))
  })

  it('Visitor', function () {
    let v = new Visitor(0)
    strictEqual(v.start, 0)
    strictEqual(v.end, 0)
    v.walk(10)
    strictEqual(v.start, 0)
    strictEqual(v.end, 10)
    v.walk(100)
    strictEqual(v.start, 10)
    strictEqual(v.end, 110)
  })

  suite('UFloat16', function () {
    function uint16Buf (val) {
      let buf = Buffer.alloc(2)
      buf.writeUInt16LE(val, 0)
      return buf
    }

    it('Float16MaxValue, readUFloat16, writeUFloat16', function () {
      let buf = Buffer.from([0xff, 0xff])
      strictEqual(readUFloat16(buf), Float16MaxValue)
      ok(writeUFloat16(Buffer.alloc(2), readUFloat16(buf), 0).equals(buf))
    })

    it('writeUFloat16', function () {
      let testCases = [
        [0, 0],
        [1, 1],
        [2, 2],
        [3, 3],
        [4, 4],
        [5, 5],
        [6, 6],
        [7, 7],
        [15, 15],
        [31, 31],
        [42, 42],
        [123, 123],
        [1234, 1234],
        // Check transition through 2^11.
        [2046, 2046],
        [2047, 2047],
        [2048, 2048],
        [2049, 2049],
        // Running out of mantissa at 2^12.
        [4094, 4094],
        [4095, 4095],
        [4096, 4096],
        [4097, 4096],
        [4098, 4097],
        [4099, 4097],
        [4100, 4098],
        [4101, 4098],
        // Check transition through 2^13.
        [8190, 6143],
        [8191, 6143],
        [8192, 6144],
        [8193, 6144],
        [8194, 6144],
        [8195, 6144],
        [8196, 6145],
        [8197, 6145],
        // Half-way through the exponents.
        [0x7FF8000, 0x87FF],
        [0x7FFFFFF, 0x87FF],
        [0x8000000, 0x8800],
        [0xFFF0000, 0x8FFF],
        [0xFFFFFFF, 0x8FFF],
        [0x10000000, 0x9000],
        // Transition into the largest exponent.
        [0x1FFFFFFFFFE, 0xF7FF],
        [0x1FFFFFFFFFF, 0xF7FF],
        [0x20000000000, 0xF800],
        [0x20000000001, 0xF800],
        [0x2003FFFFFFE, 0xF800],
        [0x2003FFFFFFF, 0xF800],
        [0x20040000000, 0xF801],
        [0x20040000001, 0xF801],
        // Transition into the max value and clamping.
        [0x3FF80000000, 0xFFFE],
        [0x3FFBFFFFFFF, 0xFFFE],
        [0x3FFC0000000, 0xFFFF],
        [0x3FFC0000001, 0xFFFF],
        [0x3FFFFFFFFFF, 0xFFFF],
        [0x40000000000, 0xFFFF],
        [0xFFFFFFFFFFFFFFFF, 0xFFFF]
      ]

      for (let data of testCases) {
        ok(writeUFloat16(Buffer.alloc(2), data[0], 0).equals(uint16Buf(data[1])))
      }
    })

    it('readUFloat16', function () {
      let testCases = [
        [0, 0],
        [1, 1],
        [2, 2],
        [3, 3],
        [4, 4],
        [5, 5],
        [6, 6],
        [7, 7],
        [15, 15],
        [31, 31],
        [42, 42],
        [123, 123],
        [1234, 1234],
        // Check transition through 2^11.
        [2046, 2046],
        [2047, 2047],
        [2048, 2048],
        [2049, 2049],
        // Running out of mantissa at 2^12.
        [4094, 4094],
        [4095, 4095],
        [4096, 4096],
        [4098, 4097],
        [4100, 4098],
        // Check transition through 2^13.
        [8190, 6143],
        [8192, 6144],
        [8196, 6145],
        // Half-way through the exponents.
        [0x7FF8000, 0x87FF],
        [0x8000000, 0x8800],
        [0xFFF0000, 0x8FFF],
        [0x10000000, 0x9000],
        // Transition into the largest exponent.
        [0x1FFE0000000, 0xF7FF],
        [0x20000000000, 0xF800],
        [0x20040000000, 0xF801],
        // Transition into the max value.
        [0x3FF80000000, 0xFFFE],
        [0x3FFC0000000, 0xFFFF]
      ]

      for (let data of testCases) {
        strictEqual(readUFloat16(uint16Buf(data[1])), data[0])
      }
    })
  })
})
