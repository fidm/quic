'use strict'
// **Github:** https://github.com/fidm/quic
//
// **License:** MIT

import { debuglog } from 'util'
import { EventEmitter } from 'events'
import {
  PingFrameDelay,
  DefaultIdleTimeout,
  MaxStreamWaitingTimeout,
  DefaultMaxIncomingStreams,
  ReceiveConnectionWindow,
  DefaultMaxReceiveConnectionWindowClient,
  DefaultMaxReceiveConnectionWindowServer,
  // DefaultMaxIncomingStreams,
 } from './internal/constant'
import {
  Offset,
  SessionType,
  StreamID,
  PacketNumber,
  ConnectionID,
  SocketAddress,
  Tag,
  QuicTags,
 } from './internal/protocol'
import {
  kID,
  kFC,
  kHS,
  kRTT,
  kStreams,
  kSocket,
  kState,
  kType,
  kVersion,
  kACKHandler,
  kNextStreamID,
  kNextPacketNumber,
  kIntervalCheck,
  kUnackedPackets,
} from './internal/symbol'
import {
  Frame,
  PingFrame,
  StreamFrame,
  RstStreamFrame,
  AckRange,
  AckFrame,
  GoAwayFrame,
  ConnectionCloseFrame,
  WindowUpdateFrame,
  StopWaitingFrame,
  BlockedFrame,
} from './internal/frame'
import { Packet, ResetPacket, RegularPacket } from './internal/packet'
import { QuicError, StreamError, QUICError } from './internal/error'
import { ConnectionFlowController } from './internal/flowcontrol'
import { RTTStats } from './internal/congestion'
import { BufferVisitor, toBuffer, Queue } from './internal/common'

import { Socket } from './socket'
import { Stream, SessionRef } from './stream'
import { HandShake } from './handshake'

const debug = debuglog('quic:session')

export declare interface Session {
  addListener (event: "error", listener: (err: Error) => void): this
  addListener (event: "goaway", listener: (err: QUICError) => void): this
  addListener (event: "close", listener: (err?: Error) => void): this
  addListener (event: "timeout", listener: () => void): this
  addListener (event: "stream", listener: (stream: Stream) => void): this

  emit (event: "error", err: Error): boolean
  emit (event: "goaway", err: QUICError): boolean
  emit (event: "close", err?: Error): boolean
  emit (event: "timeout"): boolean
  emit (event: "stream", stream: Stream): boolean

  on (event: "error", listener: (err: Error) => void): this
  on (event: "goaway", listener: (err: QUICError) => void): this
  on (event: "close", listener: (err?: Error) => void): this
  on (event: "timeout", listener: () => void): this
  on (event: "stream", listener: (stream: Stream) => void): this

  once (event: "error", listener: (err: Error) => void): this
  once (event: "goaway", listener: (err: QUICError) => void): this
  once (event: "close", listener: (err?: Error) => void): this
  once (event: "timeout", listener: () => void): this
  once (event: "stream", listener: (stream: Stream) => void): this
}

//
// *************** Session ***************
//
export class Session extends EventEmitter implements SessionRef {
  // Event: 'timeout'
  // Event: 'close'
  // Event: 'error'
  // Event: 'stream'
  // Event: 'version'
  // Event: 'goaway'

  [kID]: ConnectionID
  [kType]: SessionType
  [kIntervalCheck]: NodeJS.Timer | null
  [kStreams]: Map<number, Stream>
  [kNextStreamID]: StreamID
  [kState]: SessionState
  [kACKHandler]: ACKHandler
  [kSocket]: Socket<Session> | null
  [kVersion]: string
  [kNextPacketNumber]: PacketNumber
  [kUnackedPackets]: Queue<RegularPacket>
  [kRTT]: RTTStats
  [kFC]: ConnectionFlowController
  [kHS]: HandShake
  constructor (id: ConnectionID, type: SessionType) {
    super()

    this[kID] = id
    this[kType] = type
    this[kStreams] = new Map()
    this[kNextStreamID] = new StreamID(type === SessionType.SERVER ? 2 : 1)
    this[kState] = new SessionState()
    this[kACKHandler] = new ACKHandler()
    this[kHS] = new HandShake(this) // will be overwrite
    this[kSocket] = null
    this[kVersion] = ''
    this[kIntervalCheck] = null
    this[kNextPacketNumber] = new PacketNumber(1)
    this[kUnackedPackets] = new Queue() // up to 1000
    this[kRTT] = new RTTStats()
    this[kFC] = this.isClient ? // TODO
      new ConnectionFlowController(ReceiveConnectionWindow, DefaultMaxReceiveConnectionWindowClient) :
      new ConnectionFlowController(ReceiveConnectionWindow, DefaultMaxReceiveConnectionWindowServer)
  }

  get id (): string {
    return this[kID].valueOf()
  }

  get version (): string {
    return this[kVersion]
  }

  get isClient (): boolean {
    return this[kType] === SessionType.CLIENT
  }

  get destroyed (): boolean {
    return this[kState].destroyed
  }

  get localAddr () {
    return {
      address: this[kState].localAddress,
      family: this[kState].localFamily,
      port: this[kState].localPort,
      socketAddress: this[kState].localAddr,
    }
  }

  get remoteAddr () {
    return {
      address: this[kState].remoteAddress,
      family: this[kState].remoteFamily,
      port: this[kState].remotePort,
      socketAddress: this[kState].remoteAddr,
    }
  }

  get _stateMaxPacketSize (): number {
    return this[kState].maxPacketSize
  }

  get timeout (): number {
    return this[kState].idleTimeout
  }

  set timeout (msecs: number) {
    this[kState].idleTimeout = msecs
  }

  _stateDecreaseStreamCount () {
    this[kState].liveStreamCount -= 1
  }

  _newRegularPacket (): RegularPacket {
    const packetNumber = this[kNextPacketNumber]
    this[kNextPacketNumber] = packetNumber.nextNumber()
    return new RegularPacket(this[kID], packetNumber)
  }

  _sendFrame (frame: Frame, callback?: (...args: any[]) => void) {
    const regularPacket = this._newRegularPacket()
    regularPacket.addFrames(frame)
    regularPacket.isRetransmittable = frame.isRetransmittable()
    this._sendPacket(regularPacket, callback)
  }

  _sendStopWaitingFrame (leastUnacked: number) {
    const regularPacket = this._newRegularPacket()
    const frame = new StopWaitingFrame(regularPacket.packetNumber, leastUnacked)
    regularPacket.addFrames(frame)
    regularPacket.isRetransmittable = false

    debug(`%s session %s - write StopWaitingFrame, packetNumber: %d, leastUnacked: %d`,
      SessionType[this[kType]], this.id, frame.packetNumber.valueOf(), leastUnacked)
    this._sendPacket(regularPacket)
  }

  _retransmit (frame: AckFrame, rcvTime: number): number {
    const unackedPackets = this[kUnackedPackets]
    debug(`%s session %s - start retransmit, count: %d, ackFrame: %j`,
      SessionType[this[kType]], this.id, unackedPackets.length, frame.valueOf())

    let count = 0
    let packet = unackedPackets.first()
    while (packet != null) {
      const packetNumber = packet.packetNumber.valueOf()
      if (packetNumber > frame.largestAcked) {
        break // wait for newest ack
      } else if (packetNumber === frame.largestAcked) {
        this[kRTT].updateRTT(packet.sentTime, rcvTime, frame.delayTime)
      }

      if (frame.acksPacket(packetNumber)) {
        unackedPackets.shift()
        packet = unackedPackets.first()
        continue
      }
      unackedPackets.shift()
      packet.setPacketNumber(this[kNextPacketNumber])
      this[kNextPacketNumber] = packet.packetNumber.nextNumber()
      this._sendPacket(packet)
      count += 1
      packet = unackedPackets.first()
    }
    debug(`%s session %s - finish retransmit, count: %d`, SessionType[this[kType]], this.id, count)
    return count
  }

  _sendPacket (packet: Packet, callback?: (...args: any[]) => void) {
    const socket = this[kSocket]
    if (callback == null) {
      callback = (err) => {
        if (err != null) {
          this.destroy(err)
        }
      }
    }
    if (socket == null) {
      return callback(QuicError.fromError(QuicError.QUIC_PACKET_WRITE_ERROR))
    }
    if (socket[kState].destroyed) {
      return callback(QuicError.fromError(QuicError.QUIC_PACKET_WRITE_ERROR))
    }

    if (packet.isRegular()) {
      const _packet = packet as RegularPacket
      if (this.isClient && !this[kState].versionNegotiated) {
        _packet.setVersion(this[kVersion])
      }
      if (_packet.isRetransmittable) {
        this[kUnackedPackets].push(packet as RegularPacket)
        if (this[kUnackedPackets].length > 4096) {
          return callback(QuicError.fromError(QuicError.QUIC_TOO_MANY_OUTSTANDING_SENT_PACKETS))
        }
      }
      debug(`%s session %s - write RegularPacket, packetNumber: %d, frames: %j`,
        SessionType[this[kType]], this.id, _packet.packetNumber.valueOf(), _packet.frames.map((frame) => frame.name))
    }

    socket.sendPacket(packet, this[kState].remotePort, this[kState].remoteAddress, callback)
    // debug(`%s session %s - write packet: %j`, this.id, packet.valueOf())
  }

  _sendWindowUpdate (offset: Offset, streamID?: StreamID) {
    if (streamID == null) {
      // update for session
      streamID = new StreamID(0)
    }
    debug(`%s session %s - write WindowUpdateFrame, streamID: %d, offset: %d`,
      SessionType[this[kType]], this.id, streamID.valueOf(), offset)
    this._sendFrame(new WindowUpdateFrame(streamID, offset), (err: any) => {
      if (err != null) {
        this.emit('error', err)
      }
    })
  }

  _trySendAckFrame () {
    const frame = this[kACKHandler].toFrame()
    if (frame == null) {
      return
    }
    debug(`%s session %s - write AckFrame, lowestAcked: %d, largestAcked: %d, ackRanges: %j`,
      SessionType[this[kType]], this.id, frame.lowestAcked, frame.largestAcked, frame.ackRanges)
    frame.setDelay()
    this._sendFrame(frame, (err) => {
      if (err != null) {
        this.destroy(err)
      }
    })
  }

  _handleRegularPacket (packet: RegularPacket, rcvTime: number, bufv: BufferVisitor) {
    const packetNumber = packet.packetNumber.valueOf()
    this[kState].lastNetworkActivityTime = rcvTime

    // if (!this[kHS].completed) {
    //   this[kHS].handlePacket(packet, rcvTime, bufv)
    //   if (this[kACKHandler].ack(packetNumber, rcvTime, packet.needAck())) {
    //     this._trySendAckFrame()
    //   }
    //   return
    // }

    packet.parseFrames(bufv)
    if (this[kACKHandler].ack(packetNumber, rcvTime, packet.needAck())) {
      this._trySendAckFrame()
    }

    debug(`%s session %s - received RegularPacket, packetNumber: %d, frames: %j`,
      SessionType[this[kType]], this.id, packetNumber, packet.frames.map((frame) => frame.name))
    for (const frame of packet.frames) {
      switch (frame.name) {
        case 'STREAM':
          this._handleStreamFrame(frame as StreamFrame, rcvTime)
          break
        case 'ACK':
          this._handleACKFrame(frame as AckFrame, rcvTime)
          break
        case 'STOP_WAITING':
          // The STOP_WAITING frame is sent to inform the peer that it should not continue to
          // wait for packets with packet numbers lower than a specified value.
          // The resulting least unacked is the smallest packet number of any packet for which the sender is still awaiting an ack.
          // If the receiver is missing any packets smaller than this value,
          // the receiver should consider those packets to be irrecoverably lost.
          this._handleStopWaitingFrame(frame as StopWaitingFrame)
          break
        case 'WINDOW_UPDATE':
          this._handleWindowUpdateFrame(frame as WindowUpdateFrame)
          break
        case 'BLOCKED':
          // The BLOCKED frame is used to indicate to the remote endpoint that this endpoint is
          // ready to send data (and has data to send), but is currently flow control blocked.
          // It is a purely informational frame.
          this._handleBlockedFrame(frame as RstStreamFrame, rcvTime)
          break
        case 'CONGESTION_FEEDBACK':
          // The CONGESTION_FEEDBACK frame is an experimental frame currently not used.
          break
        case 'PADDING':
          // When this frame is encountered, the rest of the packet is expected to be padding bytes.
          return
        case 'RST_STREAM':
          this._handleRstStreamFrame(frame as RstStreamFrame, rcvTime)
          break
        case 'PING':
          // The PING frame contains no payload.
          // The receiver of a PING frame simply needs to ACK the packet containing this frame.
          break
        case 'CONNECTION_CLOSE':
          this.destroy((frame as ConnectionCloseFrame).error)
          break
        case 'GOAWAY':
          this[kState].shuttingDown = true
          this.emit('goaway', (frame as GoAwayFrame).error)
          break
      }
    }
  }

  _handleStreamFrame (frame: StreamFrame, rcvTime: number) {
    const streamID = frame.streamID.valueOf()
    let stream = this[kStreams].get(streamID)
    if (stream == null) {
      if (this[kState].shuttingDown) {
        return
      }
      stream = new Stream(frame.streamID, this, {})
      if (this[kState].liveStreamCount >= DefaultMaxIncomingStreams) {
        stream.close(QuicError.fromError(QuicError.QUIC_TOO_MANY_AVAILABLE_STREAMS))
        return
      }
      this[kStreams].set(streamID, stream)
      this[kState].liveStreamCount += 1
      this.emit('stream', stream)
    } else if (stream.destroyed) {
      return
    }
    stream._handleFrame(frame, rcvTime)
  }

  _handleRstStreamFrame (frame: RstStreamFrame, rcvTime: number) {
    const streamID = frame.streamID.valueOf()
    const stream = this[kStreams].get(streamID)
    if (stream == null || stream.destroyed) {
      return
    }
    stream._handleRstFrame(frame, rcvTime)
  }

  _handleACKFrame (frame: AckFrame, rcvTime: number) {
    // The sender must always close the connection if an unsent packet number is acked,
    // so this mechanism automatically defeats any potential attackers.
    if (frame.largestAcked >= this[kNextPacketNumber].valueOf()) {
      this.destroy(QuicError.fromError(QuicError.QUIC_INTERNAL_ERROR))
      return
    }
    // It is recommended for the sender to send the most recent largest acked packet
    // it has received in an ack as the stop waiting frame’s least unacked value.
    if (frame.hasMissingRanges()) {
      this._sendStopWaitingFrame(frame.largestAcked)
    }
    this._retransmit(frame, rcvTime)
  }

  _handleStopWaitingFrame (frame: StopWaitingFrame) {
    this[kACKHandler].lowest(frame.leastUnacked.valueOf())
  }

  _handleWindowUpdateFrame (frame: WindowUpdateFrame) {
    // The stream ID can be 0, indicating this WINDOW_UPDATE applies to the connection level flow control window,
    // or > 0 indicating that the specified stream should increase its flow control window.
    const streamID = frame.streamID.valueOf()
    const offset = frame.offset.valueOf()

    debug(`%s session %s - received WindowUpdateFrame, streamID: %d, offset: %d`,
      SessionType[this[kType]], this.id, streamID, offset)
    if (streamID === 0) {
      this[kFC].updateMaxSendOffset(offset)
    } else {
      const stream = this[kStreams].get(streamID)
      if (stream != null && !stream.destroyed) {
        if (stream[kFC].updateMaxSendOffset(offset)) {
          stream._tryFlushCallbacks()
        }
      }
    }
  }

  _handleBlockedFrame (frame: BlockedFrame, rcvTime: number) {
    this[kFC].updateBlockedFrame(frame.streamID.valueOf(), rcvTime)
  }

  _intervalCheck (time: number) {
    if (this.destroyed) {
      return
    }

    // The PING frame should be used to keep a connection alive when a stream is open.
    if (this[kState].keepAlivePingSent && this[kStreams].size > 0 && (time - this[kState].lastNetworkActivityTime >= PingFrameDelay)) {
      this.ping().catch((err) => this.emit('error', err))
    }
    for (const stream of this[kStreams].values()) {
      if (stream.destroyed) {
        // clearup idle stream
        if (time - stream[kState].lastActivityTime > this[kState].idleTimeout) {
          this[kStreams].delete(stream.id)
        }
      } else if (time - stream[kState].lastActivityTime > MaxStreamWaitingTimeout) {
        stream.emit('timeout')
      }
    }
    this._trySendAckFrame()
    return
  }

  request (options?: any): Stream {
    if (this[kState].shuttingDown) {
      throw StreamError.fromError(StreamError.QUIC_STREAM_PEER_GOING_AWAY)
    }
    if (this[kState].liveStreamCount >= DefaultMaxIncomingStreams) {
      throw QuicError.fromError(QuicError.QUIC_TOO_MANY_OPEN_STREAMS)
    }

    const streamID = this[kNextStreamID]
    this[kNextStreamID] = streamID.nextID()
    const stream = new Stream(streamID, this, (options == null ? {} : options))
    this[kStreams].set(streamID.valueOf(), stream)
    this[kState].liveStreamCount += 1
    return stream
  }

  goaway (err: any): Promise<void> {
    return new Promise((resolve) => {
      if (this[kState].shuttingDown) {
        return resolve()
      }

      this[kState].shuttingDown = true
      const frame = new GoAwayFrame(this[kNextStreamID].prevID(), QuicError.fromError(err))
      debug(`%s session %s - write GoAwayFrame, streamID: %d, error: %j`,
        SessionType[this[kType]], this.id, frame.streamID.valueOf(), frame.error)
      this._sendFrame(frame, (_e: any) => {
        resolve()
      })
    })
  }

  ping (): Promise<void> {
    return new Promise((resolve, reject) => {
      debug(`%s session %s - write PingFrame`, SessionType[this[kType]], this.id)
      this._sendFrame(new PingFrame(), (err: any) => {
        if (err != null) {
          reject(err)
        } else {
          resolve()
        }
      })
    })
  }

  close (err?: any): Promise<void> {
    return new Promise((resolve) => {
      if (this[kState].destroyed) {
        return resolve()
      }

      const frame = new ConnectionCloseFrame(QuicError.fromError(err))
      debug(`%s session %s - write ConnectionCloseFrame, error: %j`, SessionType[this[kType]], this.id, frame.error)
      this._sendFrame(frame, (e: any) => {
        this.destroy(e)
        resolve()
      })
    })
  }

  reset (_err: any): Promise<void> {
    return new Promise((resolve) => {
      if (this[kState].destroyed) {
        return resolve()
      }

      const tags = new QuicTags(Tag.PRST)
      tags.set(Tag.RNON, Buffer.allocUnsafe(8)) // TODO
      tags.set(Tag.RSEQ, toBuffer(this[kNextPacketNumber].prevNumber()))
      const localAddr = this[kState].localAddr
      if (localAddr != null) {
        tags.set(Tag.CADR, toBuffer(localAddr))
      }

      const packet = new ResetPacket(this[kID], tags)
      debug(`%s session %s - write ResetPacket, packet: %j`, SessionType[this[kType]], this.id, packet)

      this._sendPacket(packet, (e: any) => {
        this.destroy(e)
        resolve()
      })
    })
  }

  destroy (err: any) {
    if (this[kState].destroyed) {
      return
    }
    debug(`%s session %s - session destroyed, error: %j`, SessionType[this[kType]], this.id, err)

    err = QuicError.checkAny(err)
    if (err != null && err.isNoError) {
      err = null
    }

    const socket = this[kSocket]
    if (socket != null) {
      socket[kState].conns.delete(this.id)
      if (this.isClient && !socket[kState].destroyed && (socket[kState].exclusive || socket[kState].conns.size === 0)) {
        socket.close()
        socket[kState].destroyed = true
      }
      this[kSocket] = null
    }

    for (const stream of this[kStreams].values()) {
      stream.destroy(err)
    }
    const timer = this[kIntervalCheck]
    if (timer != null) {
      clearInterval(timer)
    }
    this[kStreams].clear()
    this[kUnackedPackets].reset()

    if (err != null) {
      this.emit('error', err)
    }

    if (!this[kState].destroyed) {
      this[kState].destroyed = true
      process.nextTick(() => this.emit('close'))
    }
    return
  }
}

export class SessionState {
  localFamily: string
  localAddress: string
  localPort: number
  localAddr: SocketAddress | null // SocketAddress

  remoteFamily: string
  remoteAddress: string
  remotePort: number
  remoteAddr: SocketAddress | null // SocketAddress

  maxPacketSize: number
  bytesRead: number
  bytesWritten: number
  idleTimeout: number
  liveStreamCount: number
  lastNetworkActivityTime: number

  destroyed: boolean
  shutdown: boolean
  shuttingDown: boolean
  versionNegotiated: boolean
  keepAlivePingSent: boolean

  constructor () {
    this.localFamily = ''
    this.localAddress = ''
    this.localPort = 0
    this.localAddr = null // SocketAddress

    this.remoteFamily = ''
    this.remoteAddress = ''
    this.remotePort = 0
    this.remoteAddr = null // SocketAddress

    this.maxPacketSize = 0
    this.bytesRead = 0
    this.bytesWritten = 0
    this.idleTimeout = DefaultIdleTimeout
    this.liveStreamCount = 0
    this.lastNetworkActivityTime = Date.now()

    this.destroyed = false
    this.shutdown = false
    this.shuttingDown = false // send or receive GOAWAY
    this.versionNegotiated = false
    this.keepAlivePingSent = false
  }
}

export class ACKHandler {
  misshit: number
  lowestAcked: number
  largestAcked: number
  numbersAcked: number[]
  largestAckedTime: number // timestamp
  lastAckedTime: number // timestamp
  constructor () {
    this.misshit = 0
    this.lowestAcked = 0
    this.largestAcked = 0
    this.numbersAcked = []
    this.largestAckedTime = 0
    this.lastAckedTime = Date.now()
  }

  lowest (packetNumber: number) {
    if (packetNumber > this.lowestAcked) {
      this.lowestAcked = packetNumber
    }
  }

  ack (packetNumber: number, rcvTime: number, needAck: boolean): boolean {
    if (packetNumber < this.lowestAcked) {
      return false // ignore
    }

    if (packetNumber > this.largestAcked) {
      if (packetNumber - this.largestAcked > 1) {
        this.misshit += 1
      }
      this.largestAcked = packetNumber
      this.largestAckedTime = rcvTime
    } else if (Math.abs(packetNumber - this.numbersAcked[0]) > 1) {
      this.misshit += 1
    }

    let shouldAck = this.numbersAcked.unshift(packetNumber) >= 511 // 256 blocks + 255 gaps, too many packets, should ack
    if (!needAck && this.largestAcked - this.lowestAcked <= 1) {
      // ACK frame
      this.lowestAcked = this.largestAcked
      this.numbersAcked.length = 1
      return false
    }
    if (this.misshit > 16) {
      shouldAck = true
    }
    const timeSpan = rcvTime - this.lastAckedTime
    if (timeSpan >= 512) {
      shouldAck = true
    }
    if (shouldAck) {
      debug(`should ACK, largestAcked: %d, lowestAcked: %d, misshit: %d, numbersAcked: %d, timeSpan: %d`,
        this.largestAcked, this.lowestAcked, this.misshit, this.numbersAcked.length, timeSpan)
      this.lastAckedTime = rcvTime
    }
    return shouldAck
  }

  toFrame (): AckFrame | null {
    const numbersAcked = this.numbersAcked
    if (numbersAcked.length === 0) {
      return null
    }

    numbersAcked.sort((a, b) => b - a)
    if (numbersAcked[0] <= this.lowestAcked) {
      numbersAcked.length = 0
      this.largestAcked = this.lowestAcked
      return null
    }

    const frame = new AckFrame()
    frame.largestAcked = this.largestAcked
    frame.largestAckedTime = this.largestAckedTime

    let range = new AckRange(this.largestAcked, this.largestAcked)
    // numbersAcked should include largestAcked and lowestAcked for this AGL
    for (let i = 1, l = numbersAcked.length; i < l; i++) {
      const num = numbersAcked[i]
      if (num < this.lowestAcked) {
        numbersAcked.length = i // drop smaller numbers
        break
      }
      const ret = numbersAcked[i - 1] - num
      if (ret === 1) {
        range.first = num
      } else if (ret > 1) {
        frame.ackRanges.push(range)
        range = new AckRange(num, num)
      } // else ingnore
    }

    frame.lowestAcked = range.first
    if (range.last  < frame.largestAcked) {
      frame.ackRanges.push(range)
    }

    if (frame.ackRanges.length === 0) {
      this.lowestAcked = this.largestAcked
      numbersAcked.length = 1
    } else if (frame.ackRanges.length > 256) {
      // if ackRanges.length > 256, ignore some ranges between
      frame.ackRanges[255] = frame.ackRanges[frame.ackRanges.length - 1]
      frame.ackRanges.length = 256
    }
    debug(`after build AckFrame, largestAcked: %d, lowestAcked: %d, numbersAcked: %j`,
      this.largestAcked, this.lowestAcked, numbersAcked)
    this.misshit = 0
    return frame
  }
}
