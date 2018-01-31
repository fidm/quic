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

  static fromBuffer (bufv) {
    bufv.v.walk(4)
    let pos = bufv.v.start
    let name = bufv.toString('utf8', bufv.v.start, bufv.v.end)
    let quicTag = new QuicTag(name)
    bufv.v.walk(4)
    let count = bufv.readInt32LE(bufv.v.start)

    let baseOffset = bufv.v.end + 8 * count
    let v2 = new Visitor(baseOffset)
    while (count--) {
      bufv.v.walk(4)
      let key = bufv.toString('utf8', bufv.v.start, bufv.v.end)
      bufv.v.walk(4)
      v2.walk(0)
      v2.end = baseOffset + bufv.readInt32LE(bufv.v.start)
      let val = bufv.slice(v2.start, v2.end)
      quicTag.setTag(key, val)
    }
    bufv.v.reset(v2.end, v2.end)
    quicTag.byteLen = v2.end - pos
    return quicTag
  }
}

exports.QuicTag = QuicTag
