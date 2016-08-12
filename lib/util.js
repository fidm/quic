'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

// const MAX_UINT32 = 0xffffffff

exports.allocBuffer = Buffer.allocUnsafe || function (size) { return new Buffer(size) }

exports.bufferFromBytes = function (array) {
  let bytes = array.map((val) => typeof val === 'string' ? val.charCodeAt(0) : val)
  return new Buffer(bytes)
}
//
// class UInt64 {
//   constructor (low, high) {
//     this[0] = low
//     this[1] = high
//   }
//
//   toBuffer () {
//     let buf = exports.allocBuffer(8)
//     buf.writeUInt32LE(this[0], 0, true)
//     buf.writeUInt32LE(this[1], 4, true)
//     return buf
//   }
//
//   equals (other) {
//     if (other instanceof UInt64) {
//       return this[0] === other[0] && this[1] === other[1]
//     }
//     return this[0] === other
//   }
//
//   static MAX_VALUE () {
//     return new UInt64(MAX_UINT32, MAX_UINT32)
//   }
//
//   static MIN_VALUE () {
//     return new UInt64(0, 0)
//   }
// }
//
// exports.UInt64 = UInt64
