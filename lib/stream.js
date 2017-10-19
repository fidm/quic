'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const { Duplex } = require('stream')
const { Offset } = require('./protocol')

const kID = Symbol('id')
const kSession = Symbol('session')
const kState = Symbol('state')

class Stream extends Duplex {
  /**
   * Returns a QUIC stream.
   *
   * @param {protocol.StreamID} stream id
   * @param {connection.Connection} QUIC connection
   * @return {Stream}
   */
  constructor (id, session) {
    super({ allowHalfOpen: true, readableObjectMode: false, writableObjectMode: false })
    this.cork()

    this[kID] = id
    this[kSession] = session
    this[kState] = {
      aborted: false,
      writeOffset: new Offset(),
      readOffset: new Offset()
    }
  }

  // The socket owned by this session
  get id () {
    return this[kID]
  }

  get session () {
    return this[kSession]
  }

  get aborted () {
    return this[kState].aborted
  }

  // Reset closes the stream with an error.
  // reset (err) {}

  _write (chunk, encoding, callback) {
    // The underlying source only deals with strings
    // if (Buffer.isBuffer(chunk))
    //   chunk = chunk.toString()
    // this[kSource].writeSomeData(chunk)
    // callback()
  }

  _writev (data, callback) {}

  _read (size) {
    // this[kSource].fetchSomeData(size, (data, encoding) => {
    //   this.push(Buffer.from(data, encoding))
    // })
  }
}

exports.Stream = Stream
