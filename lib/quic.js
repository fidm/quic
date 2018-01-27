'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const { Duplex } = require('stream')
const EventEmitter = require('events')
const { createSocket } = require('dgram')
const { lookup, Visitor } = require('./common')

const {
  ConnectionID,
  Offset,
  MaxReceivePacketSize,
  SocketAddress,
  QUIC_SERVER,
  QUIC_CLIENT,
  chooseVersion
} = require('./protocol')

const {
  parsePacket
} = require('../lib/packet')
const { StreamFrame } = require('./frame')
const { QuicError } = require('./error')

const debug = require('util').debuglog('quic')
const kID = Symbol('id')
const kSession = Symbol('session')
const kStreams = Symbol('streams')
const kSocket = Symbol('socket')
const kState = Symbol('state')
const kType = Symbol('type')
const kVersion = Symbol('version')
const kServer = Symbol('server')

//
// *************** Stream ***************
//

class QUICStream extends Duplex {
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

  /**
   * Returns a QUIC stream.
   *
   * @param {protocol.StreamID} stream id
   * @param {connection.Connection} QUIC connection
   * @return {Stream}
   */
  constructor (id, session, options) {
    options.allowHalfOpen = true
    options.decodeStrings = false
    options.objectMode = false
    super(options)
    this.cork()

    this[kID] = id
    this[kSession] = session
    this[kState] = new StreamState()
  }

  // The socket owned by this session
  get id () {
    return this[kID]
  }

  get session () {
    return this[kSession]
  }

  get aborted () {
    return this[kState].aborted
  }

  get closed () {}

  get destroyed () {}

  close (code) {}

  // Reset closes the stream with an error.
  reset (_err) {}

  _write (chunk, encoding, callback) {
    let streamFrame = new StreamFrame(this[kID], this[kState].writeOffset, chunk, false)
    this[kSession]._sendFrame(streamFrame, callback)
  }

  _read (size) {}
}

class StreamState {
  constructor () {
    this.aborted = false
    this.writeOffset = new Offset()
    this.readOffset = new Offset()
  }
}

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

class ServerSession extends Session {
  constructor (id, socket, server) {
    super(id, QUIC_SERVER)
    this[kSocket] = socket
    this[kServer] = server
    this[kState].localPort = server.localPort
    this[kState].localAddress = server.localAddress
    this[kState].localFamily = server.localFamily
    this[kState].localAddr = SocketAddress.fromObject(server.address())
  }

  get server () {
    return this[kServer]
  }
}

//
// *************** Server ***************
//
class Server extends EventEmitter {
  // Event: 'listening'
  // Event: 'connection'

  constructor () {
    super()
    this[kSocket] = null
    this.localFamily = ''
    this.localAddress = ''
    this.localPort = 0
    this.listening = false
    this.conns = new Map()
  }

  address () {
    return { port: this.localPort, family: this.localFamily, address: this.localAddress }
  }

  async listen (port, address) {
    if (this[kSocket]) throw new Error('Server listening')

    let addr = await lookup(address || 'localhost')
    debug(`server listen: ${address}, ${port}`, addr)

    this[kSocket] = createSocket(addr.family === 4 ? 'udp4' : 'udp6')
    this[kSocket].server = this
    this[kSocket]
      .on('error', (err) => this.emit('error', err))
      .on('close', serverOnClose)
      .on('message', serverOnMessage)

    let res = new Promise((resolve, reject) => {
      this[kSocket].once('listening', () => {
        this[kSocket].removeListener('error', reject)

        let addr = this[kSocket].address()
        this.localFamily = addr.family
        this.localAddress = addr.address
        this.localPort = addr.port
        this.listening = true
        this.emit('listening')
        resolve()
      })
      this[kSocket].once('error', reject)
    })
    // Can't support cluster
    this[kSocket].bind({ port: port, address: addr.address, exclusive: true })
    return res
  }

  close (_err) {}

  closeRemote (_err) {}

  getConnections () {
    return Promise.resolve(this.conns.size)
  }

  ref () {}

  unref () {}
}

function serverOnMessage (msg, rinfo) {
  debug(`server message: ${msg.length} bytes`, rinfo)
  // The packet size should not exceed protocol.MaxReceivePacketSize bytes
  // If it does, we only read a truncated packet, which will then end up undecryptable
  if (msg.length > MaxReceivePacketSize) {
    debug(`receive too large data: ${msg.length} bytes`)
    msg = msg.slice(0, MaxReceivePacketSize)
  }

  let senderAddr = SocketAddress.fromObject(rinfo)
  let rcvTime = Date.now()

  let bufv = Visitor.wrap(msg)
  let packet = null
  try {
    packet = parsePacket(bufv, QUIC_CLIENT)
  } catch (err) {
    debug(`parsing packet error: ${err.message}`)
    // drop this packet if we can't parse the Public Header
    return
  }

  let connectionID = packet.connectionID.toString()
  let session = this.server.conns.get(connectionID)
  let newSession = !session
  if (newSession) {
    session = new ServerSession(packet.connectionID, this, this.server)
    this.server.conns.set(connectionID, session)
  }

  if (packet.isReset()) {
    if (newSession) {
      this.server.conns.delete(connectionID)
      return
    }
    // check if the remote address and the connection ID match
    // otherwise this might be an attacker trying to inject a PUBLIC_RESET to kill the connection
    if (session[kState].remoteAddr && !this[kState].remoteAddr.equals(senderAddr)) {
      debug(`Received a spoofed Public Reset. Ignoring.`)
      return
    }

    session.closeRemote(new Error(`Received Public Reset, rejected packet number: ${packet.packetNumber}.`))
    return
  }

  // update the remote address, even if unpacking failed for any other reason than a decryption error
  session[kState].remotePort = senderAddr.port
  session[kState].remoteAddress = senderAddr.address
  session[kState].remoteFamily = senderAddr.family
  session[kState].remoteAddr = senderAddr

  if (newSession) {
    this.server.emit('session', session)
  }

  if (packet.isNegotiation()) {
    // ignore delayed / duplicated version negotiation packets
    if (session[kState].receivedNegotiationPacket || session[kState].versionNegotiated) {
      return
    }

    if (session.version && packet.versions.includes(session.version)) {
      // the version negotiation packet contains the version that we offered
      // this might be a packet sent by an attacker (or by a terribly broken server implementation)
      // ignore it
      return
    }

    session[kState].receivedNegotiationPacket = true
    let newVersion = chooseVersion(packet.versions)
    if (!newVersion) {
      session.close(new QuicError('QUIC_INVALID_VERSION'))
    }

    // switch to negotiated version
    // let initialVersion = session.version
    session.version = newVersion
    // do some other...
    return
  }

  // this is the first packet after the client sent a packet with the VersionFlag set
  // if the server doesn't send a version negotiation packet, it supports the suggested version
  if (!session[kState].versionNegotiated) {
    session[kState].versionNegotiated = true
    session.emit('version', session.version)
  }

  session._handleRegularPacket(packet, rcvTime, bufv)
}

function serverOnClose () {

}

//
// *************** Client ***************
//
class Client extends Session {
  constructor () {
    super(ConnectionID.random(), QUIC_CLIENT)
  }

  async connect (port, address) {
    if (this[kSocket]) throw new Error('Client connecting duplicated')

    let addr = await lookup(address || 'localhost')

    debug(`client connect: ${address || 'localhost'}, ${port}`, addr)
    this[kState].remotePort = port
    this[kState].remoteAddress = addr.address
    this[kState].remoteFamily = 'IPv' + addr.family
    this[kState].remoteAddr = SocketAddress.fromObject({ port: port, address: addr.address, family: 'IPv' + addr.family })

    this[kSocket] = createSocket(addr.family === 4 ? 'udp4' : 'udp6')
    this[kSocket]
      .on('error', (err) => this.emit('error', err))
      .on('close', () => clientOnClose(this))
      .on('message', (msg, rinfo) => clientOnMessage(this, msg, rinfo))

    let res = new Promise((resolve, reject) => {
      this[kSocket].once('listening', () => {
        this[kSocket].removeListener('error', reject)

        let addr = this[kSocket].address()
        this[kState].localFamily = addr.family
        this[kState].localAddress = addr.address
        this[kState].localPort = addr.port
        this[kState].localAddr = SocketAddress.fromObject(addr)
        // process.nextTick(emit, this, 'connect')
        resolve()
        this.emit('connect')
      })
      this[kSocket].once('error', reject)
    })
    this[kSocket].bind({ exclusive: true })
    return res
  }
}

function clientOnMessage (session, msg, rinfo) {
  debug(`client message: ${session.id}, ${msg.length} bytes`, rinfo)
  // The packet size should not exceed protocol.MaxReceivePacketSize bytes
  // If it does, we only read a truncated packet, which will then end up undecryptable
  if (msg.length > MaxReceivePacketSize) {
    debug(`receive too large data: ${msg.length} bytes`)
    msg = msg.slice(0, MaxReceivePacketSize)
  }

  let senderAddr = SocketAddress.fromObject(rinfo)
  let rcvTime = Date.Now()

  let bufv = Visitor.wrap(msg)
  let packet = null
  try {
    packet = parsePacket(bufv, QUIC_SERVER, session[kVersion])
  } catch (err) {
    debug(`error parsing packet for ${session.id.toString()} from ${JSON.stringify(rinfo)}: ${err.message}`)
    // drop this packet if we can't parse the Public Header
    return
  }
  // reject packets with the wrong connection ID
  if (!session.id.equals(packet.connectionID)) {
    return
  }

  if (packet.isReset()) {
    // check if the remote address and the connection ID match
    // otherwise this might be an attacker trying to inject a PUBLIC_RESET to kill the connection
    if (!this[kState].remoteAddr.equals(senderAddr)) {
      debug(`Received a spoofed Public Reset. Ignoring.`)
      return
    }

    session.closeRemote(new Error(`Received Public Reset, rejected packet number: ${packet.packetNumber}.`))
    return
  }

  if (packet.isNegotiation()) {
    // ignore delayed / duplicated version negotiation packets
    if (session[kState].receivedNegotiationPacket || session[kState].versionNegotiated) {
      return
    }

    if (session.version && packet.versions.includes(session.version)) {
      // the version negotiation packet contains the version that we offered
      // this might be a packet sent by an attacker (or by a terribly broken server implementation)
      // ignore it
      return
    }

    session[kState].receivedNegotiationPacket = true
    let newVersion = chooseVersion(packet.versions)
    if (!newVersion) {
      session.close(new QuicError('QUIC_INVALID_VERSION'))
    }

    // switch to negotiated version
    // let initialVersion = session.version
    session.version = newVersion
    // do some other...
    return
  }

  // this is the first packet after the client sent a packet with the VersionFlag set
  // if the server doesn't send a version negotiation packet, it supports the suggested version
  if (!session[kState].versionNegotiated) {
    session[kState].versionNegotiated = true
    session.emit('version', session.version)
  }

  session._handleRegularPacket(packet, rcvTime, bufv)
}

function clientOnClose (session) {

}

// Top level to avoid creating a closure
// function emit (self, ...args) {
//   self.emit(...args)
// }

exports.Stream = QUICStream
exports.Session = Session
exports.ServerSession = ServerSession
exports.Client = Client
exports.Server = Server
