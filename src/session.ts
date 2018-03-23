'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

import { EventEmitter } from 'events'
import { Socket } from 'dgram'
import {
  SessionType,
  StreamID,
  PacketNumber,
  ConnectionID,
  SocketAddress,
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
} from './internal/symbol'
import {
  Frame,
  PingFrame,
  StreamFrame,
  AckFrame,
  ConnectionCloseFrame,
} from './internal/frame'
import { Packet, RegularPacket } from './internal/packet'

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
      return callback(new Error('UDP not connect'))
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
          break
        case 'PING':
          this.emit('ping')
          break
        case 'CONNECTION_CLOSE':
          this._closeLocal((frame as ConnectionCloseFrame).error)
          break
        case 'GOAWAY':
          break
      }
    }
  }

  /**
   * @param {StreamFrame} frame
   */
  _handleStreamFrame (frame: StreamFrame) {
    const streamID = frame.streamID.valueOf()
    let stream = this[kStreams].get(streamID)
    if (stream == null) {
      stream = new Stream(frame.streamID, this, {})
      this[kStreams].set(streamID, stream)
      this.emit('stream', stream)
    }
    // TODO: ACK and reorder by offset
    stream._handleFrame(frame)
  }

  _handleACKFrame (_frame: AckFrame) {
    this[kACKHandler].ack(_frame)
  }

  request (options: any) {
    const streamID = this[kNextStreamID]
    this[kNextStreamID] = streamID.nextID()
    const stream = new Stream(streamID, this, (options == null ? {} : options))
    this[kStreams].set(streamID.valueOf(), stream)
    return stream
  }

  goaway (_code: number, _lastStreamID: StreamID, _opaqueData: Buffer) {
    return
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

  // Graceful or immediate shutdown of the Session. Graceful shutdown
  // is only supported on the server-side
  close (_err: any) {
    return
  }

  _closeRemote (_err: any) {
    return
  }
  _closeLocal (_err: any) {
    return
  }

  destroy () {
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
    this.lastNetworkActivityTime = 0

    this.destroyed = false
    this.shutdown = false
    this.shuttingDown = false
    this.versionNegotiated = false
    this.keepAlivePingSent = false
  }
}

export class ACKHandler {
  ack (_val: any) {
    return
  }
}
