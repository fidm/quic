'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

exports.allocBuffer = Buffer.allocUnsafe || function (size) { return new Buffer(size) }

exports.bufferFromBytes = function (array) {
  let bytes = array.map((val) => typeof val === 'string' ? val.charCodeAt(0) : val)
  return new Buffer(bytes)
}
