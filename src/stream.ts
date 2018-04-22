'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

import { debuglog } from 'util'
import { Duplex } from 'stream'
import { StreamError, QuicError } from './internal/error'
import {
  MaxStreamDataSize,
  MaxStreamReadCacheSize,
  ReceiveStreamWindow,
  DefaultMaxReceiveStreamWindowClient,
  DefaultMaxReceiveStreamWindowServer,
} from './internal/constant'
import {
  Offset,
  StreamID,
} from './internal/protocol'
import { StreamFrame, RstStreamFrame, BlockedFrame } from './internal/frame'
import { StreamFlowController } from './internal/flowcontrol'
import {
  kID,
  kFC,
  kSession,
  kState,
} from './internal/symbol'

import { Session } from './session'

const debug = debuglog('quic:stream')

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
  private [kFC]: StreamFlowController
  constructor (streamID: StreamID, session: Session, options: any) {
    options.allowHalfOpen = true
    options.objectMode = false
    super(options)

    this[kID] = streamID
    this[kSession] = session
    this[kState] = new StreamState()
    this[kFC] = session.isClient ? // TODO: small window will make "packets loss" test failure
      new StreamFlowController(ReceiveStreamWindow, DefaultMaxReceiveStreamWindowClient, session[kFC]) :
      new StreamFlowController(ReceiveStreamWindow, DefaultMaxReceiveStreamWindowServer, session[kFC])
    this.once('close', () => this[kState].lastActivityTime = Date.now())
    debug(`session %s - new stream: %d`, session.id, streamID.valueOf())
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

  get destroyed (): boolean {
    return this[kState].destroyed
  }

  get bytesRead (): number {
    return this[kFC].consumedOffset
  }

  get bytesWritten (): number {
    return this[kFC].writtenOffset
  }

  // close closes the stream with an error.
  close (err: any): Promise<any> {
    this[kState].localFIN = true
    const offset = new Offset(this[kFC].writtenOffset)
    const rstStreamFrame = new RstStreamFrame(this[kID], offset, StreamError.fromError(err))

    debug(`stream %s - close stream, offset: %d, error: %j`, this.id, offset.valueOf(), err)
    return new Promise((resolve) => {
      this[kSession]._sendFrame(rstStreamFrame, (e) => {
        if (e != null) {
          this.destroy(e)
        }
        resolve()
      })
    })
  }

  _write (chunk: Buffer, encoding: string, callback: (...args: any[]) => void) {
    if (this[kState].localFIN) {
      return callback(new StreamError('QUIC_RST_ACKNOWLEDGEMENT'))
    }
    if (!(chunk instanceof Buffer)) {
      chunk = Buffer.from(chunk, encoding)
    }
    if (chunk.length === 0) {
      return callback(null)
    }
    const bufs = []
    while (chunk.length > MaxStreamDataSize) {
      bufs.push(chunk.slice(0, MaxStreamDataSize))
      chunk = chunk.slice(MaxStreamDataSize)
    }
    bufs.push(chunk)
    this[kState].outgoingChunksList.push(bufs, callback)
    this._tryFlushCallbacks()
  }

  _writev (chunks: any[], callback: (...args: any[]) => void) {
    if (this[kState].localFIN) {
      return callback(new StreamError('QUIC_RST_ACKNOWLEDGEMENT'))
    }

    let len = 0
    const list = []
    for (const item of chunks) {
      // { chunk: ..., encoding: ... }
      let chunk = item.chunk
      if (!(chunk instanceof Buffer)) {
        chunk = Buffer.from(chunk, item.encoding)
      }

      len += chunk.length
      list.push(chunk)
    }
    if (len === 0) {
      return callback(null)
    }

    let buf = Buffer.concat(list, len)
    const bufs = []
    while (buf.length > MaxStreamDataSize) {
      bufs.push(buf.slice(0, MaxStreamDataSize))
      buf = buf.slice(MaxStreamDataSize)
    }
    bufs.push(buf)
    this[kState].outgoingChunksList.push(bufs, callback)
    this._tryFlushCallbacks()
  }

  _final (callback: (...args: any[]) => void): void {
    this[kState].outgoingChunksList.push([], callback)
    this._tryFlushCallbacks()
  }

  _read (size: number = 0) {
    let data = this[kState].incomingSequencer.read()
    while (data != null) {
      if (this.push(data) && size > data.length) {
        size -= data.length
        data = this[kState].incomingSequencer.read()
        continue
      }
      break
    }
    if (!this[kState].ended && this[kState].incomingSequencer.isFIN()) {
      this[kState].ended = true
      this.push(null)
    }
  }

  _destroy (err: any, callback: (...args: any[]) => void) {
    debug(`stream %s - stream destroyed, error: %j`, this.id, err)

    this[kSession][kState].liveStreamCount -= 1
    const state = this[kState]
    state.localFIN = true
    state.remoteFIN = true
    state.aborted = true
    state.destroyed = true
    state.finished = true
    state.incomingSequencer.reset()
    state.outgoingChunksList.reset()

    err = StreamError.checkAny(err)
    if (err != null && err.isNoError) {
      err = null
    }
    callback(err)
  }

  _sendBlockFrame () {
    this[kSession]._sendFrame(new BlockedFrame(this[kID]))
  }

  _trySendUpdateWindow () {
    if (this[kFC].shouldUpdateWindow()) {
      const offset = this[kFC].updateWindowOffset()
      this[kSession]._sendWindowUpdate(new Offset(offset), this[kID])
    }
  }

  _handleFrame (frame: StreamFrame, rcvTime: number) {
    this[kState].lastActivityTime = rcvTime

    const offset = frame.offset.valueOf()
    const byteLen = frame.data == null ? 0 : frame.data.length
    debug(`stream %s - received StreamFrame, offset: %d, data size: %d, isFIN: %s`,
      this.id, offset, byteLen, frame.isFIN)

    this[kFC].updateHighestReceived(offset + byteLen)
    if (this[kFC].isBlocked()) {
      this.emit('error', new Error('The window of byte offset overflowed'))
      this.close(StreamError.fromError(StreamError.QUIC_ERROR_PROCESSING_STREAM))
      return
    }

    if (frame.isFIN) {
      this[kState].remoteFIN = true
      this[kState].incomingSequencer.setFinalOffset(offset + byteLen)
    }
    if (frame.data != null) {
      if (this[kState].incomingSequencer.hasOffset(offset)) {
        return // duplicated frame
      }

      this[kState].incomingSequencer.push(frame)
      if (!frame.isFIN) {
        this._trySendUpdateWindow()
      }
    }

    this._read(MaxStreamDataSize * 10) // try to read all
    this[kFC].updateConsumedOffset(this[kState].incomingSequencer.consumedOffset)
    if (this[kState].incomingSequencer.byteLen > MaxStreamReadCacheSize) {
      this.emit('error', new Error('Too large caching, stream data maybe lost'))
      this.destroy(StreamError.fromError(StreamError.QUIC_ERROR_PROCESSING_STREAM))
      return
    }
  }

  _handleRstFrame (frame: RstStreamFrame, rcvTime: number) {
    this[kState].lastActivityTime = rcvTime
    this[kState].remoteFIN = true
    this[kState].incomingSequencer.setFinalOffset(frame.offset.valueOf())
    debug(`stream %s - received RstStreamFrame, offset: %d, error: %j`, this.id, frame.offset.valueOf(), frame.error)
    if (this[kState].localFIN) {
      this.destroy(frame.error)
    } else {
      this.emit('error', frame.error)
      this.close(StreamError.fromError(StreamError.QUIC_RST_ACKNOWLEDGEMENT))
    }
    return
  }

  _tryFlushCallbacks () {
    const entry = this[kState].outgoingChunksList.first()
    if (entry == null || this[kState].flushing) {
      return
    }

    if (entry.data.length > 0 && !this._isRemoteWriteable(entry.data[0].length)) {
      return
    }

    const callback = entry.callback
    this[kState].flushing = true
    this._flushData(entry.data, (err) => {
      this[kState].flushing = false
      if (entry.data.length === 0) {
        this[kState].outgoingChunksList.shift()
        callback(err)
      }

      if (err == null && this[kState].outgoingChunksList.pendingCb > 0) {
        return this._tryFlushCallbacks()
      }
    })
  }

  private _isRemoteWriteable (byteLen: number): boolean {
    if (this[kFC].willBlocked(byteLen)) {
      // should wait for WINDOW_UPDATE
      debug(`stream %s - wait for WINDOW_UPDATE, writtenOffset: %d, maxSendOffset: %d, to write size: %d`,
        this.id, this[kFC].writtenOffset, this[kFC].maxSendOffset, byteLen)
      this._sendBlockFrame()
      return false
    }
    return true
  }

  private _flushData (fixedChunks: Buffer[], callback: (err: any) => void): void {
    const buf = fixedChunks.shift()
    const offet = new Offset(this[kFC].writtenOffset)
    const byteLen = buf == null ? 0 : buf.length
    if (byteLen > 0) {
      this[kFC].updateWrittenOffset(byteLen)
    }
    const streamFrame = new StreamFrame(this[kID], offet, buf, buf == null)
    if (streamFrame.isFIN) {
      this[kState].localFIN = true
    }

    debug(`stream %s - write streamFrame, isFIN: %s, offset: %d, data size: %d`,
      this.id, streamFrame.isFIN, streamFrame.offset.valueOf(), byteLen)
    this[kSession]._sendFrame(streamFrame, (err) => {
      if (err != null || fixedChunks.length === 0 || !this._isRemoteWriteable(fixedChunks[0].length)) {
        return callback(err)
      }

      this._flushData(fixedChunks, callback)
    })
  }
}

class StreamState {
  localFIN: boolean
  remoteFIN: boolean
  flushing: boolean
  ended: boolean
  aborted: boolean
  destroyed: boolean
  finished: boolean
  lastActivityTime: number
  incomingSequencer: StreamSequencer
  outgoingChunksList: StreamChunksList
  constructor () {
    this.localFIN = false // local endpoint will not send data
    this.remoteFIN = false // remote endpoint should not send data
    this.flushing = false
    this.ended = false
    this.aborted = false
    this.destroyed = false
    this.finished = false
    this.lastActivityTime = Date.now()
    this.incomingSequencer = new StreamSequencer()
    this.outgoingChunksList = new StreamChunksList()
  }
}

class StreamChunksEntry {
  data: Buffer[]
  callback: (...args: any[]) => void
  next: StreamChunksEntry | null
  byteLen: number
  constructor (bufs: Buffer[], callback: (...args: any[]) => void, entry: StreamChunksEntry | null) {
    this.data = bufs
    this.callback = callback
    this.next = entry
    this.byteLen = 0
    for (const chunk of bufs) {
      if (chunk.length > MaxStreamDataSize) {
        throw new QuicError(`chunk size too large: ${chunk.length}`)
      }
      this.byteLen += chunk.length
    }
  }
}

class StreamChunksList {
  head: StreamChunksEntry | null
  tail: StreamChunksEntry | null
  pendingCb: number
  byteLen: number
  constructor () {
    this.head = null
    this.tail = null
    this.pendingCb = 0
    this.byteLen = 0
  }

  reset () {
    this.head = null
    this.tail = null
    this.pendingCb = 0
    this.byteLen = 0
  }

  push (bufs: Buffer[], callback: (...args: any[]) => void) {
    const entry = new StreamChunksEntry(bufs, callback, null)

    if (this.tail != null) {
      this.tail.next = entry
    } else {
      this.head = entry
    }
    this.tail = entry
    this.pendingCb += 1
    this.byteLen += entry.byteLen
  }

  first (): StreamChunksEntry | null {
    return this.head
  }

  shift (): StreamChunksEntry | null {
    if (this.head == null) {
      return null
    }
    const entry = this.head
    if (this.pendingCb === 1) {
      this.head = this.tail = null
    } else {
      this.head = this.head.next
    }
    this.pendingCb -= 1
    this.byteLen -= entry.byteLen
    return entry
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

// sequencer
class StreamSequencer {
  head: StreamFrameEntry | null
  byteLen: number
  consumedOffset: number
  finalOffset: number
  pendingOffsets: Set<number>
  constructor () {
    this.head = null
    this.byteLen = 0
    this.consumedOffset = 0
    this.finalOffset = -1
    this.pendingOffsets = new Set()
  }

  hasOffset (offset: number): boolean {
    if (offset < this.consumedOffset) {
      return true
    }
    return this.pendingOffsets.has(offset)
  }

  reset () {
    this.head = null
    this.byteLen = 0
    this.consumedOffset = 0
    this.finalOffset = -1
    this.pendingOffsets.clear()
  }

  setFinalOffset (offset: number) {
    this.finalOffset = offset
  }

  isFIN (): boolean {
    return this.consumedOffset === this.finalOffset
  }

  /**
   * @param {StreamFrame}
   */
  push (frame: StreamFrame) {
    const entry = new StreamFrameEntry(frame, null)
    const offset = entry.offset
    this.pendingOffsets.add(offset)
    if (entry.data != null) {
      this.byteLen += entry.data.length
    }

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
    if (this.head != null && this.consumedOffset === this.head.offset) {
      data = this.head.data
      if (data != null) {
        this.pendingOffsets.delete(this.consumedOffset)
        this.byteLen -= data.length
        this.consumedOffset += data.length
      }
      this.head = this.head.next
    }
    return data
  }
}
