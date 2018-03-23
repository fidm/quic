'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

import { Duplex } from 'stream'
import { QuicStreamError } from './internal/error'
import {
  Offset,
  StreamID,
  MaxStreamBufferSize,
} from './internal/protocol'
import { StreamFrame, RstStreamFrame } from './internal/frame'
import {
  kID,
  kSession,
  kState,
} from './internal/symbol'

import { Session } from './session'

export class Stream extends Duplex {
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

  private [kID]: StreamID
  private [kSession]: Session
  private [kState]: StreamState
  constructor (streamID: StreamID, session: Session, options: any) {
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
  get id (): number {
    return this[kID].valueOf()
  }

  get session (): Session {
    return this[kSession]
  }

  get aborted (): boolean {
    return this[kState].aborted
  }

  // get closed (): boolean {
  // }

  // get destroyed (): boolean {}

  close (_code: any): void {
    return
  }

  // Reset closes the stream with an error.
  reset (err: Error): Promise<number> {
    this[kState].localFIN = true
    const offset = this[kState].writeOffset
    const rstStreamFrame = new RstStreamFrame(this[kID], offset, QuicStreamError.fromError(err))
    return new Promise((resolve, reject) => {
      this[kSession]._sendFrame(rstStreamFrame, (e) => {
        if (e != null) {
          reject(e)
        } else {
          resolve(offset.valueOf())
        }
      })
    })
  }

  _handleFrame (frame: StreamFrame): void {
    if (frame.data != null) {
      this[kState].bytesRead += frame.data.length
      this[kState].readQueue.push(frame)
    }
    if (frame.isFIN && !this[kState].remoteFIN) {
      this[kState].remoteFIN = true
      this[kState].readQueue.setEndOffset(frame.offset.valueOf())
    }

    this._read(MaxStreamBufferSize * 10) // try to read all
  }

  _flushData (shouldFin: boolean, callback: (...args: any[]) => void): void {
    const buf = this[kState].bufferList.read(MaxStreamBufferSize)
    if (buf == null && !shouldFin) {
      return callback()
    }

    const offet = this[kState].writeOffset
    if (buf != null) {
      this[kState].writeOffset = offet.nextOffset(buf.length)
    }
    const streamFrame = new StreamFrame(this[kID], offet, buf, (shouldFin && this[kState].bufferList.length === 0))
    if (streamFrame.isFIN) {
      this[kState].localFIN = true
    }
    this[kSession]._sendFrame(streamFrame, (err: any) => {
      if (err != null) {
        return callback(err)
      }
      if (this[kState].bufferList.length === 0) {
        return callback()
      }
      this._flushData(shouldFin, callback)
    })
  }

  _write (chunk: Buffer, _encoding: string, callback: (...args: any[]) => void): void {
    if (this[kState].localFIN) {
      return callback(new QuicStreamError('QUIC_RST_ACKNOWLEDGEMENT'))
    }
    if (!(chunk instanceof Buffer)) {
      return callback(new Error('invalid data'))
    }
    this[kState].bufferList.push(chunk)
    this._flushData(false, callback)
  }

  _final (callback: (...args: any[]) => void): void {
    this._flushData(true, callback)
  }

  _read (size: number = 0) {
    const data = this[kState].readQueue.read()
    if (data != null) {
      if (this.push(data) && size > data.length) {
        this._read(size - data.length)
        return
      }
    }
    if (!this[kState].ended && this[kState].readQueue.isEnd()) {
      this[kState].ended = true
      this.push(null)
    }
  }
}

class StreamState {
  localFIN: boolean
  remoteFIN: boolean
  ended: boolean
  aborted: boolean
  finished: boolean
  bytesRead: number
  bytesWritten: number
  readQueue: StreamFramesSorter
  bufferList: StreamDataList
  writeOffset: Offset
  constructor () {
    this.localFIN = false // local endpoint will not send data
    this.remoteFIN = false // remote endpoint should not send data
    this.ended = false
    this.aborted = false
    this.finished = false
    this.bytesRead = 0
    this.bytesWritten = 0
    this.readQueue = new StreamFramesSorter()
    this.bufferList = new StreamDataList()
    this.writeOffset = new Offset(0)
  }
}

class StreamDataEntry {
  data: Buffer
  next: StreamDataEntry | null
  constructor (buf: Buffer, entry: StreamDataEntry | null) {
    this.data = buf
    this.next = entry
  }
}

class StreamDataList {
  head: StreamDataEntry | null
  tail: StreamDataEntry | null
  length: number
  constructor () {
    this.head = null
    this.tail = null
    this.length = 0
  }

  push (buf: Buffer): void {
    const entry = new StreamDataEntry(buf, null)

    if (this.tail != null) {
      this.tail.next = entry
    } else {
      this.head = entry
    }
    this.tail = entry
    this.length += 1
  }

  shift () {
    if (this.head == null) {
      return null
    }
    const ret = this.head.data
    if (this.length === 1) {
      this.head = this.tail = null
    } else {
      this.head = this.head.next
    }
    this.length -= 1
    return ret
  }

  read (n: number): Buffer | null {
    if (this.head == null) {
      return null
    }

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

class StreamFrameEntry {
  data: Buffer | null
  offset: number
  next: StreamFrameEntry | null
  constructor (frame: StreamFrame, entry: StreamFrameEntry | null) {
    this.data = frame.data
    this.offset = frame.offset.valueOf()
    this.next = entry
  }
}

class StreamFramesSorter {
  head: StreamFrameEntry | null
  readOffset: number
  endOffset: number
  constructor () {
    this.head = null
    this.readOffset = 0
    this.endOffset = -1
  }

  setEndOffset (offset: number) {
    this.endOffset = offset
  }

  isEnd (): boolean {
    return this.readOffset === this.endOffset
  }

  /**
   * @param {StreamFrame}
   */
  push (frame: StreamFrame) {
    const entry = new StreamFrameEntry(frame, null)
    const offset = entry.offset

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

  read (): Buffer | null {
    let data = null
    if (this.head != null && this.readOffset === this.head.offset) {
      data = this.head.data
      this.readOffset = this.head.offset + (data != null ? data.length : 0)
      this.head = this.head.next
    }
    return data
  }
}
