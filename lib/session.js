'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const EventEmitter = require('events')
const {
  QUIC_SERVER,
  QUIC_CLIENT,
  StreamID,
  PacketNumber
 } = require('./internal/protocol')
const {
  kID,
  kStreams,
  kSocket,
  kState,
  kType,
  kVersion,
  kNextStreamID,
  kNextPacketNumber
} = require('./internal/symbol')
const {
  PingFrame
  // StreamFrame
} = require('./internal/frame')
const { RegularPacket } = require('./internal/packet')

const { QUICStream } = require('./stream')

//
// *************** Session ***************
//
class Session extends EventEmitter {
  // Event: 'timeout'
  // Event: 'close'
  // Event: 'error'
  // Event: 'stream'
  // Event: 'version'

  constructor (id, type) {
    super()

    this[kID] = id
    this[kType] = type // 0: QUIC_SERVER or 1: QUIC_CLIENT
    this[kStreams] = new Map()
    this[kNextStreamID] = StreamID.fromValue(type === QUIC_SERVER ? 0 : 1)
    this[kState] = new SessionState()
    this[kSocket] = null
    this[kVersion] = ''
    this[kNextPacketNumber] = PacketNumber.fromValue(1)
    this.setMaxListeners((2 ** 31) - 1)
  }

  get id () {
    return this[kID].value
  }

  get version () {
    return this[kVersion]
  }

  get isClient () {
    return this[kType] === QUIC_CLIENT
  }

  // true if the Http2Session has been destroyed
  get destroyed () {
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

  _sendFrame (frame, callback) {
    let packetNumber = this[kNextPacketNumber]
    this[kNextPacketNumber] = packetNumber.nextNumber()
    let regularPacket = new RegularPacket(this[kID], packetNumber, null, '')
    regularPacket.addFrames(frame)
    this._sendPacket(regularPacket, callback)
  }

  // _onPacket (packet) {}
  _sendPacket (packet, callback) {
    let buf = packet.toBuffer()
    if (!this[kSocket]) return callback(new Error('UDP not connect'))
    this[kSocket].send(buf, this[kState].remotePort, this[kState].remoteAddress, callback)
  }

  _handleRegularPacket (packet, rcvTime, bufv) {
    if (this.isClient && packet.nonce) {
      // TODO
      // this.cryptoSetup.SetDiversificationNonce(packet.nonce)
    }

    this[kState].lastNetworkActivityTime = rcvTime
    this[kState].keepAlivePingSent = false
    for (let frame of packet.frames) {
      switch (frame.name) {
        case 'STREAM':
          this._handleStreamFrame(frame)
          break
        case 'ACK':
          this._handleACKFrame(frame)
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
          this.closeRemote(frame.error)
          break
        case 'GOAWAY':
          break
      }
    }
  }

  /**
   * @param {StreamFrame} frame
   */
  _handleStreamFrame (frame) {
    let streamID = frame.streamID.value
    let stream = this[kStreams].get(streamID)
    if (!stream) {
      stream = new QUICStream(frame.streamID, this, {})
      this[kStreams].set(streamID, stream)
      this.emit('stream', stream)
    }
    // TODO: ACK and reorder by offset
    stream._handleFrame(frame)
  }

  _handleACKFrame (frame) {}

  request (options) {
    let streamID = this[kNextStreamID]
    this[kNextStreamID] = streamID.nextID()
    let stream = new QUICStream(streamID, this, options || {})
    this[kStreams].set(streamID.value, stream)
    return stream
  }

  goaway (code, lastStreamID, opaqueData) {}

  ping () {
    return new Promise((resolve, reject) => {
      this._sendFrame(new PingFrame(), (err) => {
        if (err != null) reject(err)
        else resolve()
      })
    })
  }

  setTimeout (msecs) {}

  // Graceful or immediate shutdown of the Session. Graceful shutdown
  // is only supported on the server-side
  close () {}

  closeRemote (_err) {}

  destroy () {}

  ref () {}

  unref () {}
}

class SessionState {
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

exports.Session = Session
