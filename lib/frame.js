'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

// const assert = require('assert')
const allocBuffer = require('./util').allocBuffer

class QuicTag {
  constructor (name) {
    this.name = name
    this.keys = []
    this.values = {}
  }

  setTag (key, val) {
    if (this.values[key] == null) this.keys.push(key)
    this.values[key] = val
  }

  getTags () {
    return this.values
  }

  toBuffer () {
    let byteLen = 8
    for (let key of this.keys) byteLen += 8 + this.values[key].length

    let buf = allocBuffer(byteLen).fill(0)
    buf.write(this.name, 0, 4)
    buf.writeUIntLE(this.keys.length, 4, 4, true)
    let offset1 = 8
    let offset2 = 0
    let offset3 = offset1 + 8 * this.keys.length
    for (let key of this.keys) {
      let val = this.values[key]
      buf.write(key, offset1, 4)
      offset1 += 4
      offset2 += val.length
      buf.writeUIntLE(offset2, offset1, 4, true)
      offset1 += 4
      val.copy(buf, offset3, 0, val.length)
      offset3 += val.length
    }
    return buf
  }

  static fromBuffer (buf, offset, byteLen) {
    if (offset > 0 && byteLen > 0) buf = buf.slice(offset, byteLen)
    let name = buf.toString('utf8', 0, 4)
    let quicTag = new QuicTag(name)
    let count = buf.readInt32LE(4)
    let offset1 = 8
    let offset2 = offset1 + 8 * count
    while (count--) {
      let key = buf.toString('utf8', offset1, offset1 + 4)
      offset1 += 4
      let valEnd = buf.readInt32LE(offset1)
      offset1 += 4
      let val = buf.slice(offset2, offset2 + valEnd)
      quicTag.setTag(key, val)
      offset2 += valEnd
    }
    return quicTag
  }
}

exports.QuicTag = QuicTag
