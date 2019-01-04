'use strict'
// **Github:** https://github.com/fidm/quic
//
// **License:** MIT

import { debuglog } from 'util'
import { Duplex } from 'stream'
import { StreamError } from './internal/error'
import {
  MaxStreamReadCacheSize,
  ReceiveStreamWindow,
  DefaultMaxReceiveStreamWindowClient,
  DefaultMaxReceiveStreamWindowServer,
} from './internal/constant'
import {
  Offset,
  StreamID,
} from './internal/protocol'
import { Frame, StreamFrame, RstStreamFrame, BlockedFrame } from './internal/frame'
import { StreamFlowController, ConnectionFlowController } from './internal/flowcontrol'
import { RTTStats } from './internal/congestion'
import { BufferVisitor } from './internal/common'
import { Packet, RegularPacket } from './internal/packet'
import {
  kID,
  kFC,
  kVersion,
  kSession,
  kState,
  kRTT,
} from './internal/symbol'

const debug = debuglog('quic:stream')

// avoid circular references
export interface SessionRef {
  id: string
  isClient: boolean
  [kVersion]: string
  [kFC]: ConnectionFlowController
  [kRTT]: RTTStats
  _stateMaxPacketSize: number
  request (options?: any): Stream
  _stateDecreaseStreamCount (): void
  _sendFrame (frame: Frame, callback?: (...args: any[]) => void): void
  _sendWindowUpdate (offset: Offset, streamID?: StreamID): void
  _newRegularPacket (): RegularPacket
  _sendPacket (packet: Packet, callback?: (...args: any[]) => void): void
}

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
  private [kSession]: SessionRef
  private [kState]: StreamState
  private [kFC]: StreamFlowController
  constructor (streamID: StreamID, session: SessionRef, options: any) {
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

  get closing(): boolean {
    return this[kState].localFIN
  }

  // close closes the stream with an error.
  close (err: any, callback?: Function): Promise<any> {
    if(typeof err == "function"){
      callback = err
      err = 0
    }

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
        if(callback) callback()
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

    this[kState].outgoingChunksList.push(chunk, callback)
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

    this[kState].outgoingChunksList.push(Buffer.concat(list, len), callback)
    this._tryFlushCallbacks()
  }

  _final (callback: (...args: any[]) => void): void {
    this[kState].outgoingChunksList.push(null, callback)
    try {
      this._tryFlushCallbacks()
    }catch(ex){
      debug("Exception occurred while finalizing: %s", ex)
      // Ignore exceptions here
    }
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

    this[kFC].updateConsumedOffset(this[kState].incomingSequencer.consumedOffset)
    if (!this[kState].remoteFIN) {
      process.nextTick(() => this._trySendUpdateWindow())
    }

    if (!this[kState].ended && this[kState].incomingSequencer.isFIN()) {
      this[kState].ended = true
      this.push(null)
    }
  }

  _destroy (err: any, callback: (...args: any[]) => void) {
    debug(`stream %s - stream destroyed, error: %j`, this.id, err)

    this[kSession]._stateDecreaseStreamCount()
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
      const offset = this[kFC].updateWindowOffset(this[kSession][kRTT].msRTT)
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
    }

    this._read()
    if (this[kState].incomingSequencer.byteLen > MaxStreamReadCacheSize) {
      this.emit('error', new Error('Too large caching, stream data maybe lost'))
      this.destroy(StreamError.fromError(StreamError.QUIC_ERROR_PROCESSING_STREAM))
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

    if (entry.data != null && !this._isRemoteWriteable(this[kSession]._stateMaxPacketSize)) {
      return
    }

    const callback = entry.callback
    this[kState].flushing = true
    this._flushData(entry.data, (err) => {
      this[kState].flushing = false
      if (entry.checkConsumed()) {
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

  private _flushData (bufv: BufferVisitor | null, callback: (err: any) => void): void {
    let byteLen = 0 // bytes to write
    let nextByteLen = 0 // bytes for next write
    const offet = new Offset(this[kFC].writtenOffset)
    const streamFrame = new StreamFrame(this[kID], offet, bufv == null)
    const packet = this[kSession]._newRegularPacket()

    if (bufv != null) {
      byteLen = Math.min(bufv.length - bufv.end,
          this[kSession]._stateMaxPacketSize - packet.headerLen() - streamFrame.headerLen(true))

      bufv.walk(byteLen)
      nextByteLen = Math.min(byteLen, bufv.length - bufv.end)
      streamFrame.setData(bufv.buf.slice(bufv.start, bufv.end))
      this[kFC].updateWrittenOffset(byteLen)
    }

    if (streamFrame.isFIN) {
      this[kState].localFIN = true
    }

    debug(`stream %s - write streamFrame, isFIN: %s, offset: %d, data size: %d`,
      this.id, streamFrame.isFIN, streamFrame.offset.valueOf(), byteLen)
    packet.addFrames(streamFrame)
    packet.isRetransmittable = true
    this[kSession]._sendPacket(packet, (err) => {
      // Packet Number length maybe increase 1 byte
      if (err != null || nextByteLen === 0 || !this._isRemoteWriteable(nextByteLen + 1)) {
        return callback(err)
      }

      this._flushData(bufv, callback)
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
  lastActivityTime?: number
  startTime: number
  incomingSequencer: StreamSequencer
  outgoingChunksList: StreamDataList
  constructor () {
    this.localFIN = false // local endpoint will not send data
    this.remoteFIN = false // remote endpoint should not send data
    this.flushing = false
    this.ended = false
    this.aborted = false
    this.destroyed = false
    this.finished = false
    this.startTime = Date.now()
    this.incomingSequencer = new StreamSequencer()
    this.outgoingChunksList = new StreamDataList()
  }
}

class StreamDataEntry {
  callback: (...args: any[]) => void
  next: StreamDataEntry | null
  data: BufferVisitor | null
  constructor (callback: (...args: any[]) => void, buf: Buffer | null) {
    this.callback = callback
    this.next = null
    this.data = buf == null ? null : new BufferVisitor(buf)
  }

  get byteLen (): number {
    return this.data == null ? 0 : this.data.length
  }

  checkConsumed (): boolean {
    return this.data == null || this.data.end === this.data.length
  }
}

class StreamDataList {
  head: StreamDataEntry | null
  tail: StreamDataEntry | null
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

  push (buf: Buffer | null, callback: (...args: any[]) => void) {
    const entry = new StreamDataEntry(callback, buf)

    if (this.tail != null) {
      this.tail.next = entry
    } else {
      this.head = entry
    }
    this.tail = entry
    this.pendingCb += 1
    this.byteLen += entry.byteLen
  }

  first (): StreamDataEntry | null {
    return this.head
  }

  shift (): StreamDataEntry | null {
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
