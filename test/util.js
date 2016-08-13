'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const util = require('../lib/util')

exports.allocBuffer = util.allocBuffer
exports.bufferFromBytes = function (array) {
  let bytes = []
  if (!Array.isArray(array)) array = [array]
  for (let val of array) {
    if (typeof val !== 'string') bytes.push(val)
    else {
      for (let byte of new Buffer(val, 'utf8').values()) bytes.push(byte)
    }
  }
  return new Buffer(bytes)
}
