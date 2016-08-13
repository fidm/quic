'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

exports.allocBuffer = Buffer.alloc || ((size) => new Buffer(size).fill(0))

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
