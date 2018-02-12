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
  SocketAddress
 } from './internal/protocol'
 import {
  kID,
  kStreams,
  kSocket,
  kState,
  kType,
  kVersion,
  kNextStreamID,
  kNextPacketNumber
} from './internal/symbol'
import {
  Frame,
  PingFrame,
  StreamFrame,
  AckFrame,
  ConnectionCloseFrame
} from './internal/frame'
import { Packet, RegularPacket } from './internal/packet'

import { Stream } from './stream'
import { BufferVisitor, toBuffer } from './internal/common';

const kACKHandler = Symbol('ACKHandler')

//
// *************** Session ***************
//
export class Session extends EventEmitter {
  // Event: 'timeout'
  // Event: 'close'
  // Event: 'error'
  // Event: 'stream'
  // Event: 'version'

  private [kID]: ConnectionID
  private [kType]: SessionType
  private [kStreams]: Map<number, Stream>
  private [kNextStreamID]: StreamID
  private [kState]: SessionState
  private [kACKHandler]: ACKHandler
  private [kSocket]: Socket | null
  private [kVersion]: string
  private [kNextPacketNumber]: PacketNumber
  constructor (id: ConnectionID, type: SessionType) {
    super()

    this[kID] = id
    this[kType] = type
    this[kStreams] = new Map()
    this[kNextStreamID] = new StreamID(type === SessionType.SERVER ? 0 : 1)
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

  // true if the Http2Session has been destroyed
  get destroyed (): boolean {
    return this[kState].destroyed
  }

  get localAddr () {
    return {
      port: this[kState].localPort,
      family: this[kState].localFamily,
      address: this[kState].localAddress,
      socketAddress: this[kState].localAddr
    }
  }

  get remoteAddr () {
    return {
      port: this[kState].remotePort,
      family: this[kState].remoteFamily,
      address: this[kState].remoteAddress,
      socketAddress: this[kState].remoteAddr
    }
  }

  _sendFrame (frame: Frame, callback: (...args: any[]) => void) {
    let packetNumber = this[kNextPacketNumber]
    this[kNextPacketNumber] = packetNumber.nextNumber()
    let regularPacket = new RegularPacket(this[kID], packetNumber, null, '')
    regularPacket.addFrames(frame)
    this._sendPacket(regularPacket, callback)
  }

  // _onPacket (packet) {}
  _sendPacket (packet: Packet, callback: (...args: any[]) => void) {

    let buf = toBuffer(packet)
    let socket = this[kSocket]
    if (!socket) return callback(new Error('UDP not connect'))
    socket.send(buf, this[kState].remotePort, this[kState].remoteAddress, callback)
  }

  _handleRegularPacket (packet: RegularPacket, rcvTime: number, _bufv: BufferVisitor) {
    if (this.isClient && packet.nonce) {
      // TODO
      // this.cryptoSetup.SetDiversificationNonce(packet.nonce)
    }

    this[kState].lastNetworkActivityTime = rcvTime
    this[kState].keepAlivePingSent = false
    for (let frame of packet.frames) {
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
    let streamID = frame.streamID.valueOf()
    let stream = this[kStreams].get(streamID)
    if (!stream) {
      stream = new Stream(frame.streamID, this, {})
      this[kStreams].set(streamID, stream)
      this.emit('stream', stream)
    }
    // TODO: ACK and reorder by offset
    stream._handleFrame(frame)
  }

  _handleACKFrame (_frame: AckFrame) {}

  request (options: any) {
    let streamID = this[kNextStreamID]
    this[kNextStreamID] = streamID.nextID()
    let stream = new Stream(streamID, this, options || {})
    this[kStreams].set(streamID.valueOf(), stream)
    return stream
  }

  goaway (_code: number, _lastStreamID: StreamID, _opaqueData: Buffer) {}

  ping () {
    return new Promise((resolve, reject) => {
      this._sendFrame(new PingFrame(), (err: any) => {
        if (err != null) reject(err)
        else resolve()
      })
    })
  }

  setTimeout (_msecs: number) {}

  // Graceful or immediate shutdown of the Session. Graceful shutdown
  // is only supported on the server-side
  close (_err: any) {}

  _closeRemote (_err: any) {}
  _closeLocal (_err: any) {}

  destroy () {}

  ref () {}

  unref () {}
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
  keepAlivePingSent: false

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
    this.keepAlivePingSent = false
  }
}

class ACKHandler {}
