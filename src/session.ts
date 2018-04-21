'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

import { debuglog } from 'util'
import { EventEmitter } from 'events'
import { randomBytes } from 'crypto'
import {
  Offset,
  SessionType,
  StreamID,
  PacketNumber,
  ConnectionID,
  SocketAddress,
  QuicTag,
  PingFrameDelay,
  DefaultIdleTimeout,
  MaxStreamWaitingTimeout,
 } from './internal/protocol'
import {
  kID,
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
} from './internal/frame'
import { Packet, ResetPacket, RegularPacket } from './internal/packet'
import { QuicError, StreamError } from './internal/error'

import { Socket, sendPacket } from './socket'
import { Stream } from './stream'
import { BufferVisitor, toBuffer, Queue } from './internal/common'

const debug = debuglog('quic:session')

//
// *************** Session ***************
//
export class Session extends EventEmitter {
  // Event: 'timeout'
  // Event: 'close'
  // Event: 'error'
  // Event: 'stream'
  // Event: 'version'
  // Event: 'goaway'

  protected [kID]: ConnectionID
  protected [kType]: SessionType
  protected [kIntervalCheck]: NodeJS.Timer | null
  protected [kStreams]: Map<number, Stream>
  protected [kNextStreamID]: StreamID
  protected [kState]: SessionState
  protected [kACKHandler]: ACKHandler
  protected [kSocket]: Socket | null
  protected [kVersion]: string
  protected [kNextPacketNumber]: PacketNumber
  protected [kUnackedPackets]: Queue<RegularPacket>
  constructor (id: ConnectionID, type: SessionType) {
    super()

    this[kID] = id
    this[kType] = type
    this[kStreams] = new Map()
    this[kNextStreamID] = new StreamID(type === SessionType.SERVER ? 2 : 1)
    this[kState] = new SessionState()
    this[kACKHandler] = new ACKHandler()
    this[kSocket] = null
    this[kVersion] = ''
    this[kIntervalCheck] = null
    this[kNextPacketNumber] = new PacketNumber(1)
    this[kUnackedPackets] = new Queue() // up to 1000
    this.setMaxListeners((2 ** 31) - 1)
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

  _sendFrame (frame: Frame, callback: (...args: any[]) => void) {
    const packetNumber = this[kNextPacketNumber]
    this[kNextPacketNumber] = packetNumber.nextNumber()
    const regularPacket = new RegularPacket(this[kID], packetNumber, randomBytes(32))
    regularPacket.addFrames(frame)
    regularPacket.isRetransmittable = frame.isRetransmittable()
    this._sendPacket(regularPacket, callback)
  }

  _sendStopWaitingFrame (leastUnacked: number) {
    const packetNumber = this[kNextPacketNumber]
    this[kNextPacketNumber] = packetNumber.nextNumber()
    const frame = new StopWaitingFrame(packetNumber, leastUnacked)
    const regularPacket = new RegularPacket(this[kID], packetNumber, randomBytes(32))
    regularPacket.addFrames(frame)
    regularPacket.isRetransmittable = false

    debug(`session %s - write StopWaitingFrame, packetNumber: %d, leastUnacked: %d`, this.id, packetNumber.valueOf(), leastUnacked)
    this._sendPacket(regularPacket, (err) => {
      if (err != null) {
        this.destroy(err)
      }
    })
  }

  _retransmit (frame: AckFrame): number {
    const unackedPackets = this[kUnackedPackets]

    let packet = unackedPackets.first()
    let count = 0
    debug(`session %s - start retransmit, count: %d, ackFrame: %j`, this.id, unackedPackets.length, frame.valueOf())
    while (packet != null) {
      const packetNumber = packet.packetNumber.valueOf()
      if (packetNumber > frame.largestAcked) {
        break // wait for newest ack
      }

      if (frame.acksPacket(packetNumber)) {
        unackedPackets.shift()
        packet = unackedPackets.first()
        continue
      }
      unackedPackets.shift()
      packet.setPacketNumber(this[kNextPacketNumber])
      this[kNextPacketNumber] = packet.packetNumber.nextNumber()
      this._sendPacket(packet, (err) => {
        if (err != null) {
          this.destroy(err)
        }
      })
      count += 1
      packet = unackedPackets.first()
    }
    debug(`session %s - finish retransmit, count: %d`, this.id, count)
    return count
  }

  _sendPacket (packet: Packet, callback: (...args: any[]) => void) {
    const socket = this[kSocket]
    if (socket == null) {
      return callback(QuicError.fromError(QuicError.QUIC_PACKET_WRITE_ERROR))
    }
    if (socket[kState].destroyed) {
      return callback(QuicError.fromError(QuicError.QUIC_PACKET_WRITE_ERROR))
    }

    if (packet.isRegular()) {
      if (this.isClient && !this[kState].versionNegotiated) {
        (packet as RegularPacket).setVersion(this[kVersion])
      }
      if ((packet as RegularPacket).isRetransmittable) {
        this[kUnackedPackets].push(packet as RegularPacket)
        if (this[kUnackedPackets].length > 4096) {
          return callback(QuicError.fromError(QuicError.QUIC_TOO_MANY_OUTSTANDING_SENT_PACKETS))
        }
      }
    }
    sendPacket(socket, packet, this[kState].remotePort, this[kState].remoteAddress, callback)
    // debug(`session %s - write packet: %j`, this.id, packet.valueOf())
    // const buf = toBuffer(packet)
    // socket.send(buf, this[kState].remotePort, this[kState].remoteAddress, callback)
  }

  _trySendAckFrame () {
    const frame = this[kACKHandler].toFrame()
    if (frame == null) {
      return
    }
    debug(`session %s - write AckFrame, lowestAcked: %d, largestAcked: %d, ackRanges: %j`,
      this.id, frame.lowestAcked, frame.largestAcked, frame.ackRanges)
    this._sendFrame(frame, (err) => {
      if (err != null) {
        this.destroy(err)
      }
    })
  }

  _handleRegularPacket (packet: RegularPacket, rcvTime: number, _bufv: BufferVisitor) {
    if (this.isClient && packet.nonce != null) {
      // TODO
      // this.cryptoSetup.SetDiversificationNonce(packet.nonce)
    }

    const packetNumber = packet.packetNumber.valueOf()

    this[kState].lastNetworkActivityTime = rcvTime
    if (this[kACKHandler].ack(packetNumber, rcvTime, packet.needAck())) {
      this._trySendAckFrame()
    }
    debug(`session %s - received RegularPacket, packetNumber: %d, frames: %j`,
      this.id, packetNumber, packet.frames.map((frame) => frame.name))
    for (const frame of packet.frames) {
      switch (frame.name) {
        case 'STREAM':
          this._handleStreamFrame(frame as StreamFrame, rcvTime)
          break
        case 'ACK':
          this._handleACKFrame(frame as AckFrame)
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
          this.emit('goaway')
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
      this[kStreams].set(streamID, stream)
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

  _handleACKFrame (frame: AckFrame) {
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
    this._retransmit(frame)
  }

  _handleStopWaitingFrame (frame: StopWaitingFrame) {
    this[kACKHandler].lowest(frame.leastUnacked.valueOf())
  }

  _handleWindowUpdateFrame (frame: WindowUpdateFrame) {
    // The stream ID can be 0, indicating this WINDOW_UPDATE applies to the connection level flow control window,
    // or > 0 indicating that the specified stream should increase its flow control window.
    const streamID = frame.streamID.valueOf()
    const offset = frame.offset.valueOf()

    debug(`session %s - received WindowUpdateFrame, streamID: %d, offset: %d`,
      this.id, streamID, offset)
    if (streamID === 0) {
      if (offset > this[kState].outgoingWindowByteOffset) {
        this[kState].outgoingWindowByteOffset = offset
      }
    } else {
      const stream = this[kStreams].get(streamID)
      if (stream != null && !stream.destroyed) {
        if (offset > stream[kState].outgoingWindowByteOffset) {
          stream[kState].outgoingWindowByteOffset = offset
          stream._tryFlushCallbacks()
        }
      }
    }
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

  _windowUpdate (offset: Offset, streamID?: StreamID) {
    if (streamID == null) {
      // update for session
      streamID = new StreamID(0)
    }
    debug(`session %s - write WindowUpdateFrame, streamID: %d, offset: %d`, this.id, streamID.valueOf(), offset)
    this._sendFrame(new WindowUpdateFrame(streamID, offset), (err: any) => {
      if (err != null) {
        this.emit('error', err)
      }
    })
  }

  request (options?: any) {
    if (this[kState].shuttingDown) {
      throw StreamError.fromError(StreamError.QUIC_STREAM_PEER_GOING_AWAY)
    }
    const streamID = this[kNextStreamID]
    this[kNextStreamID] = streamID.nextID()
    const stream = new Stream(streamID, this, (options == null ? {} : options))
    const _streamID = streamID.valueOf()
    this[kStreams].set(_streamID, stream)
    return stream
  }

  goaway (err: any): Promise<void> {
    return new Promise((resolve) => {
      if (this[kState].shuttingDown) {
        return resolve()
      }

      this[kState].shuttingDown = true
      const frame = new GoAwayFrame(this[kNextStreamID].prevID(), QuicError.fromError(err))
      debug(`session %s - write GoAwayFrame, streamID: %d, error: %j`, this.id, frame.streamID.valueOf(), frame.error)
      this._sendFrame(frame, (_e: any) => {
        resolve()
      })
    })
  }

  ping (): Promise<void> {
    return new Promise((resolve, reject) => {
      debug(`session %s - write PingFrame`, this.id)
      this._sendFrame(new PingFrame(), (err: any) => {
        if (err != null) {
          reject(err)
        } else {
          resolve()
        }
      })
    })
  }

  setTimeout (_msecs: number) {
    return
  }

  close (err?: any): Promise<void> {
    return new Promise((resolve) => {
      if (this[kState].destroyed) {
        return resolve()
      }

      const frame = new ConnectionCloseFrame(QuicError.fromError(err))
      debug(`session %s - write ConnectionCloseFrame, error: %j`, this.id, frame.error)
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

      const tags = new QuicTag('PRST')
      tags.setTag('RNON', Buffer.allocUnsafe(8)) // TODO
      tags.setTag('RSEQ', toBuffer(this[kNextPacketNumber].prevNumber()))
      const localAddr = this[kState].localAddr
      if (localAddr != null) {
        tags.setTag('CADR', toBuffer(localAddr))
      }

      const packet = new ResetPacket(this[kID], tags)
      debug(`session %s - write ResetPacket, packet: %j`, this.id, packet)

      this._sendPacket(packet, (e: any) => {
        this.destroy(e)
        resolve()
      })
    })
  }

  destroy (err: any) {
    debug(`session %s - session destroyed, error: %j`, this.id, err)
    if (this[kState].destroyed) {
      return
    }

    err = QuicError.checkAny(err)
    if (err != null && err.isNoError) {
      err = null
    }

    const socket = this[kSocket]
    if (socket != null) {
      socket[kState].conns.delete(this.id)
      if (this.isClient && !socket[kState].destroyed && (socket[kState].exclusive || socket[kState].conns.size === 0)) {
        socket.close()
        socket.removeAllListeners()
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

  ref () {
    return
  }

  unref () {
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

  pendingAck: number
  bytesRead: number
  bytesWritten: number
  idleTimeout: number
  lastNetworkActivityTime: number

  destroyed: boolean
  shutdown: boolean
  shuttingDown: boolean
  versionNegotiated: boolean
  keepAlivePingSent: boolean
  maxIncomingByteOffset: number
  outgoingWindowByteOffset: number

  constructor () {
    this.localFamily = ''
    this.localAddress = ''
    this.localPort = 0
    this.localAddr = null // SocketAddress

    this.remoteFamily = ''
    this.remoteAddress = ''
    this.remotePort = 0
    this.remoteAddr = null // SocketAddress

    this.pendingAck = 0
    this.bytesRead = 0
    this.bytesWritten = 0
    this.idleTimeout = DefaultIdleTimeout
    this.lastNetworkActivityTime = Date.now()

    this.destroyed = false
    this.shutdown = false
    this.shuttingDown = false // send or receive GOAWAY
    this.versionNegotiated = false
    this.keepAlivePingSent = false
    // Both stream and session windows start with a default value of 16 KB
    this.maxIncomingByteOffset = 16 * 1024
    this.outgoingWindowByteOffset = 16 * 1024
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
    if (!needAck && this.largestAcked - this.lowestAcked === 1) {
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
