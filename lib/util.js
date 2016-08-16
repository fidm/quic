'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

class Visitor {
  constructor (start, end) {
    this.start = start
    this.end = end || start
  }

  walk (steps) {
    this.start = this.end
    this.end += steps
  }
}
exports.Visitor = Visitor

// We define an unsigned 16-bit floating point value, inspired by IEEE floats
// (http://en.wikipedia.org/wiki/Half_precision_floating-point_format),
// with 5-bit exponent (bias 1), 11-bit mantissa (effective 12 with hidden
// bit) and denormals, but without signs, transfinites or fractions. Wire format
// 16 bits (little-endian byte order) are split into exponent (high 5) and
// mantissa (low 11)
// https://github.com/google/proto-quic/blob/master/src/net/quic/core/quic_protocol.h#L197
const Float16ExponentBits = 5
const Float16MantissaBits = 16 - Float16ExponentBits             // 11
const Float16MantissaEffectiveBits = Float16MantissaBits + 1     // 12
const Float16MantissaEffectiveValue = 1 << Float16MantissaEffectiveBits
// Float16MaxValue === readUFloat16(<Buffer 0xff 0xff>)
const Float16MaxValue = 0x3FFC0000000
exports.Float16MaxValue = Float16MaxValue
exports.readUFloat16 = function (buf, offset) {
  let value = buf.readUInt16BE(offset || 0)
  if (value < Float16MantissaEffectiveValue) return value
  let exponent = value >> Float16MantissaBits
  --exponent
  value -= exponent << Float16MantissaBits
  // we can only use binary bitwise operators in 32 bits
  let res = value * Math.pow(2, exponent)
  return res < Float16MaxValue ? res : Float16MaxValue
}

exports.writeUFloat16 = function (value) {
  let res = 0
  if (value < Float16MantissaEffectiveValue) res = value
  else if (value >= Float16MaxValue) res = 0xffff
  else {
    let exponent = 0
    for (let offset = 16; offset >= 1; offset /= 2) {
      if (value >= (1 << (Float16MantissaBits + offset))) {
        exponent += offset
        value /= Math.pow(2, offset)
      }
    }
    res = Math.floor(value) + (exponent << Float16MantissaBits)
  }
  let buf = Buffer.alloc(2)
  buf.writeUInt16BE(res, 0)
  return buf
}
