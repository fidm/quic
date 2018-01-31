'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const EventEmitter = require('events')
const { QUIC_CLIENT } = require('./internal/protocol')
const {
  kID,
  kStreams,
  kSocket,
  kState,
  kType,
  kVersion
} = require('./internal/symbol')

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
    this[kState] = new SessionState()
    this[kSocket] = null
    this[kVersion] = ''
    this.setMaxListeners((2 ** 31) - 1)
  }

  get id () {
    return this[kID]
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

  _sendFrame (frame, callback) {}

  // _onPacket (packet) {}

  _sendPacket (packet, callback) {
    let buf = packet.toBuffer()
    if (!this[kSocket]) return callback(new Error('UDP not connect'))
    this[kSocket].send(buf, this[kState].remotePort, this[kState].remoteAddress, callback)
  }

  _handleRegularPacket (packet, rcvTime, bufv) {
    if (this.isClient() && packet.nonce) {
      // TODO
      // this.cryptoSetup.SetDiversificationNonce(packet.nonce)
    }

    this[kState].lastNetworkActivityTime = rcvTime
    this[kState].keepAlivePingSent = false
  }

  openStream () {}

  // Graceful or immediate shutdown of the Session. Graceful shutdown
  // is only supported on the server-side
  shutdown () {}

  destroy () {}

  localAddr () {
    return {
      port: this[kState].localPort,
      family: this[kState].localFamily,
      address: this[kState].localAddress,
      socketAddress: this[kState].localAddr
    }
  }

  remoteAddr () {
    return {
      port: this[kState].remotePort,
      family: this[kState].remoteFamily,
      address: this[kState].remoteAddress,
      socketAddress: this[kState].remoteAddr
    }
  }

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
    this.versionNegotiated = false
    this.receivedNegotiationPacket = false
  }
}

exports.Session = Session
