'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const EventEmitter = require('events')
const kID = Symbol('id')
// const kSession = Symbol('session')
const kStreams = Symbol('streams')
const kSocket = Symbol('socket')
const kState = Symbol('state')
const kType = Symbol('type')
const kServer = Symbol('server')

const SESSION_SERVER = 0
const SESSION_CLIENT = 1

class Session extends EventEmitter {
  // Event: 'timeout'
  // Event: 'close'
  // Event: 'error'
  // Event: 'stream'

  constructor (type, socket) {
    super()

    this[kID] = null
    this[kSocket] = socket
    this[kType] = type // 0: SESSION_SERVER or 1: SESSION_CLIENT
    this[kStreams] = new Map()
    this[kState] = {
      destroyed: false,
      shutdown: false,
      shuttingDown: false,
      pendingAck: 0,
      bytesRead: 0,
      bytesWritten: 0,
      localFamily: '',
      localAddress: '',
      localPort: 0,
      remoteFamily: '',
      remoteAddress: '',
      remotePort: 0
    }
    this.setMaxListeners((2 ** 31) - 1)
  }

  // The socket owned by this session
  get id () {
    return this[kID]
  }

  // The socket owned by this session
  get socket () {
    return this[kSocket]
  }

  // The session type
  get type () {
    return this[kType]
  }

  // true if the Http2Session has been destroyed
  get destroyed () {
    return this[kState].destroyed
  }

  _onPacket (packet) {}

  _sendPacket (packet) {
    return new Promise((resolve, reject) => {
      let buf = packet.toBuffer()
      if (!this[kSocket]) return reject(new Error('UDP not connect'))
      this[kSocket].send(buf, this[kState].remotePort, this[kState].remoteAddress, (err) => {
        if (err != null) reject(err)
        else resolve()
      })
    })
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
      address: this[kState].localAddress
    }
  }

  remoteAddr () {
    return {
      port: this[kState].remotePort,
      family: this[kState].remoteFamily,
      address: this[kState].remoteAddress
    }
  }

  ref () {}

  unref () {}
}

class ServerSession extends Session {
  constructor (socket, server) {
    super(SESSION_SERVER, socket)
    this[kServer] = server
  }

  get server () {
    return this[kServer]
  }
}

class ClientSession extends Session {
  constructor (socket) {
    super(SESSION_CLIENT, socket)
  }
}

exports.Session = Session
exports.ServerSession = ServerSession
exports.ClientSession = ClientSession
