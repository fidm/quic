'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const { Duplex } = require('stream')
const { Offset } = require('./internal/protocol')
const { StreamFrame } = require('./internal/frame')
const {
  kID,
  kSession,
  kState
} = require('./internal/symbol')

class QUICStream extends Duplex {
  // Event: 'close'
  // Event: 'connect'
  // Event: 'data'
  // Event: 'drain'
  // Event: 'end'
  // Event: 'error'
  // Event: 'timeout'
  // Event: 'aborted'
  // Event: 'finish'
  // Event: 'frameError'

  /**
   * Returns a QUIC stream.
   *
   * @param {protocol.StreamID} stream id
   * @param {connection.Connection} QUIC connection
   * @return {Stream}
   */
  constructor (streamID, session, options) {
    options.allowHalfOpen = true
    options.decodeStrings = false
    options.objectMode = false
    super(options)
    // this.cork()

    this[kID] = streamID
    this[kSession] = session
    this[kState] = new StreamState()
  }

  // The socket owned by this session
  get id () {
    return this[kID].value
  }

  get session () {
    return this[kSession]
  }

  get aborted () {
    return this[kState].aborted
  }

  get closed () {}

  get destroyed () {}

  close (code) {}

  // Reset closes the stream with an error.
  reset (_err) {}

  _write (chunk, encoding, callback) {
    let streamFrame = new StreamFrame(this[kID], this[kState].writeOffset, chunk, false)
    this[kSession]._sendFrame(streamFrame, callback)
  }

  _read (size) {}
}

class StreamState {
  constructor () {
    this.aborted = false
    this.writeOffset = Offset.fromValue(0)
    this.readOffset = Offset.fromValue(0)
  }
}

exports.QUICStream = QUICStream
