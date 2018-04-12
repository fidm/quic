'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

import { EventEmitter } from 'events'
import {
  SessionType,
  StreamID,
  PacketNumber,
  ConnectionID,
  SocketAddress,
  QuicTag,
  DefaultIdleTimeout,
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
} from './internal/symbol'
import {
  Frame,
  PingFrame,
  StreamFrame,
  RstStreamFrame,
  AckFrame,
  GoAwayFrame,
  ConnectionCloseFrame,
} from './internal/frame'
import { Packet, ResetPacket, RegularPacket } from './internal/packet'
import { QuicError } from './internal/error'

import { Socket } from './socket'
import { Stream } from './stream'
import { BufferVisitor, toBuffer } from './internal/common'

//
// *************** Session ***************
//
export class Session extends EventEmitter {
  // Event: 'timeout'
  // Event: 'close'
  // Event: 'error'
  // Event: 'stream'
  // Event: 'version'

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
    const regularPacket = new RegularPacket(this[kID], packetNumber)
    regularPacket.addFrames(frame)
    this._sendPacket(regularPacket, callback)
  }

  // _onPacket (packet) {}
  _sendPacket (packet: Packet, callback: (...args: any[]) => void) {
    if (this.isClient && !this[kState].versionNegotiated && packet.isRegular()) {
      (packet as RegularPacket).setVersion(this[kVersion])
    }

    const buf = toBuffer(packet)
    const socket = this[kSocket]
    if (socket == null) {
      return callback(new Error('the underlying socket not connect or destroyed'))
    }
    if (socket[kState].destroyed) {
      return callback(new Error('the underlying socket closed'))
    }
    socket.send(buf, this[kState].remotePort, this[kState].remoteAddress, callback)
  }

  _handleRegularPacket (packet: RegularPacket, rcvTime: number, _bufv: BufferVisitor) {
    if (this.isClient && packet.nonce != null) {
      // TODO
      // this.cryptoSetup.SetDiversificationNonce(packet.nonce)
    }

    this[kState].lastNetworkActivityTime = rcvTime
    this[kState].keepAlivePingSent = false
    for (const frame of packet.frames) {
      switch (frame.name) {
        case 'STREAM':
          this._handleStreamFrame(frame as StreamFrame)
          break
        case 'ACK':
          this._handleACKFrame(frame as AckFrame)
          break
        case 'STOP_WAITING':
          break
        case 'WINDOW_UPDATE':
          break
        case 'BLOCKED':
          break
        case 'CONGESTION_FEEDBACK':
          break
        case 'PADDING':
          break
        case 'RST_STREAM':
          this._handleRstStreamFrame(frame as RstStreamFrame)
          break
        case 'PING':
          this.emit('ping')
          break
        case 'CONNECTION_CLOSE':
          this.destroy((frame as ConnectionCloseFrame).error)
          break
        case 'GOAWAY':
          this[kState].shuttingDown = true
          break
      }
    }
  }

  _handleStreamFrame (frame: StreamFrame) {
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
    // TODO: ACK and reorder by offset
    stream._handleFrame(frame)
  }

  _handleRstStreamFrame (frame: RstStreamFrame) {
    const streamID = frame.streamID.valueOf()
    const stream = this[kStreams].get(streamID)
    if (stream == null || stream.destroyed) {
      return
    }
    // TODO: ACK and reorder by offset
    stream._handleRstFrame(frame)
  }

  _handleACKFrame (_frame: AckFrame) {
    this[kACKHandler].ack(_frame)
  }

  _intervalCheck (time: number) {
    for (const stream of this[kStreams].values()) {
      // clearup idle stream
      if (stream.destroyed && (time - stream[kState].lastActivityTime > this[kState].idleTimeout)) {
        this[kStreams].delete(stream.id)
      }
    }
    return
  }

  request (options: any) {
    if (this[kState].shuttingDown) {
      throw new Error('connection goaway')
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
      this._sendFrame(new GoAwayFrame(this[kNextStreamID].prevID(), QuicError.fromError(err)), (_e: any) => {
        resolve()
      })
    })
  }

  ping (): Promise<any> {
    return new Promise((resolve, reject) => {
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

  close (err: any): Promise<void> {
    return new Promise((resolve) => {
      if (this[kState].destroyed) {
        return resolve()
      }

      this._sendFrame(new ConnectionCloseFrame(QuicError.fromError(err)), (e: any) => {
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
      this._sendPacket(packet, (e: any) => {
        this.destroy(e)
        resolve()
      })
    })
  }

  destroy (err: any) {
    const socket = this[kSocket]
    if (socket != null) {
      if (this.isClient && !socket[kState].destroyed) {
        socket.close()
        socket[kState].destroyed = true
      }
      this[kSocket] = null
    }

    for (const stream of this[kStreams].values()) {
      stream.destroy(new Error('the underlying session destroyed'))
    }
    const timer = this[kIntervalCheck]
    if (timer != null) {
      clearInterval(timer)
    }
    this[kStreams].clear()

    if (err != null) {
      this.emit('error', err)
    }

    if (!this[kState].destroyed) {
      this[kState].destroyed = true
      this.emit('close')
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
  }
}

export class ACKHandler {
  ack (_val: any) {
    return
  }
}
