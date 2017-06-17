'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const { Visitor } = require('./common')

class QuicTag {
  constructor (name) {
    this.name = name
    this.keys = []
    this.values = {}
    this.byteLen = 0
  }

  setTag (key, val) {
    if (this.values[key] == null) this.keys.push(key)
    this.values[key] = val
  }

  getTags () {
    return this.values
  }

  toBuffer () {
    this.byteLen = 8
    for (let key of this.keys) this.byteLen += 8 + this.values[key].length

    let v1 = new Visitor(0, 4)
    let buf = Buffer.alloc(this.byteLen).fill(0)
    buf.write(this.name, v1.start, 4)
    v1.walk(4)
    buf.writeUInt32LE(this.keys.length, v1.start, true)
    let baseOffset = 0
    let v2 = new Visitor(v1.end + 8 * this.keys.length)
    for (let key of this.keys) {
      let val = this.values[key]
      v1.walk(4)
      buf.write(key, v1.start, 4)
      v1.walk(4)
      baseOffset += val.length
      buf.writeUInt32LE(baseOffset, v1.start, true)
      v2.walk(val.length)
      val.copy(buf, v2.start, 0, val.length)
    }
    return buf
  }

  static fromBuffer (buf, offset) {
    offset = offset || 0
    let v1 = new Visitor(offset, offset + 4)
    let name = buf.toString('utf8', v1.start, v1.end)
    let quicTag = new QuicTag(name)
    v1.walk(4)
    let count = buf.readInt32LE(v1.start)
    let baseOffset = v1.end + 8 * count
    let v2 = new Visitor(baseOffset)
    while (count--) {
      v1.walk(4)
      let key = buf.toString('utf8', v1.start, v1.end)
      v1.walk(4)
      v2.walk(0)
      v2.end = baseOffset + buf.readInt32LE(v1.start)
      let val = buf.slice(v2.start, v2.end)
      quicTag.setTag(key, val)
    }
    quicTag.byteLen = v2.end - offset
    return quicTag
  }
}

exports.QuicTag = QuicTag
