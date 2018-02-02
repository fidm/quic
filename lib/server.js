'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const EventEmitter = require('events')
const { createSocket } = require('dgram')

const { lookup, Visitor } = require('./internal/common')
const { parsePacket } = require('./internal/packet')
const { QuicError } = require('./internal/error')
const {
  kSocket,
  kState,
  kServer
} = require('./internal/symbol')
const {
  MaxReceivePacketSize,
  SocketAddress,
  QUIC_SERVER,
  QUIC_CLIENT,
  chooseVersion
} = require('./internal/protocol')

const { Session } = require('./session')
const debug = require('util').debuglog('quic')

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

        resolve()
        this.emit('listening')
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

  let connectionID = packet.connectionID.value
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

  session[kState].bytesRead += msg.length
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

// Top level to avoid creating a closure
// function emit (self, ...args) {
//   self.emit(...args)
// }

exports.ServerSession = ServerSession
exports.Server = Server
