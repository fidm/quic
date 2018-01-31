'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const { promisify } = require('util')

exports.lookup = promisify(require('dns').lookup)

class Visitor {
  constructor (start, end) {
    this.start = start || 0
    this.end = end || this.start
  }

  reset (start, end) {
    this.start = start || 0
    if (this.end < this.start) this.end = this.start
    if (end > this.start) this.end = end
    return this
  }

  walk (steps) {
    this.start = this.end
    this.end += steps
    return this
  }

  static wrap (buf) {
    buf.v = new Visitor()
    return buf
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
  let value = buf.readUInt16LE(offset || 0)
  if (value < Float16MantissaEffectiveValue) return value
  let exponent = value >> Float16MantissaBits
  --exponent
  value -= exponent << Float16MantissaBits
  // we can only use binary bitwise operators in 32 bits
  let res = value * Math.pow(2, exponent)
  return res < Float16MaxValue ? res : Float16MaxValue
}

exports.writeUFloat16 = function (buf, value, offset) {
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
  buf.writeUInt16LE(res, offset)
  return buf
}

class Queue {
  constructor () {
    this.tail = []
    this.head = []
    this.offset = 0
    this.hLength = 0
  }

  get length () {
    return this.hLength + this.tail.length - this.offset
  }

  first () {
    return this.hLength === this.offset ? this.tail[0] : this.head[this.offset]
  }

  push (item) {
    this.tail.push(item)
  }

  pop () {
    if (this.tail.length) return this.tail.pop()
    if (!this.hLength) return
    this.hLength--
    return this.head.pop()
  }

  unshift (item) {
    if (!this.offset) {
      this.hLength++
      this.head.unshift(item)
    } else {
      this.offset--
      this.head[this.offset] = item
    }
  }

  shift () {
    if (this.offset === this.hLength) {
      if (!this.tail.length) return

      let tmp = this.head
      tmp.length = 0
      this.head = this.tail
      this.tail = tmp
      this.offset = 0
      this.hLength = this.head.length
    }
    return this.head[this.offset++]
  }

  reset () {
    this.offset = 0
    this.hLength = 0
    this.tail.length = 0
    this.head.length = 0
  }

  migrateTo (queue) {
    let i = this.offset
    let len = this.tail.length
    while (i < this.hLength) queue.push(this.head[i++])

    i = 0
    while (i < len) queue.push(this.tail[i++])
    this.offset = this.hLength = this.head.length = this.tail.length = 0
    return queue
  }
}

exports.Queue = Queue
