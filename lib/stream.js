'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const { Duplex } = require('stream')
const { Offset } = require('./protocol')

class Stream extends Duplex {
  /**
   * Returns a QUIC stream.
   *
   * @param {protocol.StreamID} stream id
   * @param {connection.Connection} QUIC connection
   * @return {Stream}
   */
  constructor (id, conn) {
    super({allowHalfOpen: true, readableObjectMode: false, writableObjectMode: false})

    this.id = id
    this.conn = conn
    this.writeOffset = new Offset()
    this.readOffset = new Offset()
  }

  _write (chunk, encoding, callback) {
    // The underlying source only deals with strings
    // if (Buffer.isBuffer(chunk))
    //   chunk = chunk.toString()
    // this[kSource].writeSomeData(chunk)
    // callback()
  }

  _read (size) {
    // this[kSource].fetchSomeData(size, (data, encoding) => {
    //   this.push(Buffer.from(data, encoding))
    // })
  }
}

exports.Stream = Stream
