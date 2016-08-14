'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

exports.bufferFromBytes = function (array) {
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
