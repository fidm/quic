'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const { Duplex } = require('stream')
const {
  Offset,
  MaxStreamBufferSize
} = require('./internal/protocol')
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
   * @param {StreamID} streamID
   * @param {Session} session
   * @param {Object} options
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

  _handleFrame (frame) {
    if (frame.data != null) {
      this.bytesRead += frame.data.length
      this[kState].readQueue.push(frame)
      this._read(MaxStreamBufferSize * 10) // try to read all
    }
    if (frame.data == null || frame.isFIN) {
      // TODO end stream
      this[kState].finished = true
      this.push(null)
    }
  }

  _flushData (shouldFin, callback) {
    let buf = this[kState].bufferList.read(MaxStreamBufferSize)
    if (buf == null && !shouldFin) return callback()

    let offet = this[kState].writeOffset
    if (buf != null) {
      this[kState].writeOffset = offet.nextOffset(buf.length)
    }
    let streamFrame = new StreamFrame(this[kID], offet, buf, (shouldFin && this[kState].bufferList.length === 0))
    this[kSession]._sendFrame(streamFrame, (err) => {
      if (err != null) return callback(err)
      if (this[kState].bufferList.length === 0) return callback()
      this._flushData(shouldFin, callback)
    })
  }

  _write (chunk, encoding, callback) {
    if (!(chunk instanceof Buffer)) return callback(new Error('invalid data'))
    this[kState].bufferList.push(chunk)
    this._flushData(false, callback)
  }

  _final (callback) {
    this._flushData(true, callback)
  }

  _read (size) {
    let data = this[kState].readQueue.read()
    if (data != null) {
      if (this.push(data) && data.length < size) {
        this._read(size - data.length)
      }
    }
  }
}

class StreamState {
  constructor () {
    this.aborted = false
    this.finished = false
    this.bytesRead = 0
    this.bytesWritten = 0
    this.readQueue = new StreamFramesSorter()
    this.bufferList = new StreamDataList()
    this.writeOffset = Offset.fromValue(0)
  }
}

class StreamDataList {
  constructor () {
    this.head = null
    this.tail = null
    this.length = 0
  }

  /**
   * @param {Buffer}
   */
  push (buf) {
    let entry = new StreamDataEntry(buf, null)

    if (this.length > 0) {
      this.tail.next = entry
    } else {
      this.head = entry
    }
    this.tail = entry
    this.length += 1
  }

  shift () {
    if (this.length === 0) return null
    let ret = this.head.data
    if (this.length === 1) {
      this.head = this.tail = null
    } else {
      this.head = this.head.next
    }
    this.length -= 1
    return ret
  }

  /**
   * @return {?Buffer}
   */
  read (n) {
    if (this.length === 0) return null

    let ret = this.head.data
    if (ret.length > n) {
      this.head.data = ret.slice(n)
      ret = ret.slice(0, n)
      return ret
    }
    this.shift()
    return ret // ret.length <= n
  }
}

class StreamDataEntry {
  /**
   * @param {Buffer} buf
   * @param {?StreamDataEntry} entry
   */
  constructor (buf, entry) {
    this.data = buf
    this.next = entry
  }
}

class StreamFramesSorter {
  constructor () {
    this.head = null
    this.readOffset = 0
  }

  /**
   * @param {StreamFrame}
   */
  push (frame) {
    let entry = new StreamFrameEntry(frame, null)
    let offset = entry.offset

    if (this.head == null) {
      this.head = entry
    } else if (this.head.offset > offset) {
      entry.next = this.head
      this.head = entry
    } else {
      let prev = this.head
      while (true) {
        if (prev.next == null) {
          prev.next = entry
          break
        }
        if (prev.next.offset > offset) {
          entry.next = prev.next
          prev.next = entry
          break
        }
        prev = prev.next
      }
    }
  }

  /**
   * @return {?Buffer}
   */
  read () {
    let data = null
    if (this.head != null && this.readOffset >= this.head.offset) {
      data = this.head.data
      this.readOffset = this.head.offset + data.length
      this.head = this.head.next
    }
    return data
  }
}

class StreamFrameEntry {
  /**
   * @param {StreamFrame} buf
   * @param {?StreamFrameEntry} entry
   */
  constructor (frame, entry) {
    this.data = frame.data
    this.offset = frame.offset.value
    this.next = entry
  }
}

exports.QUICStream = QUICStream
