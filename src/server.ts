'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

import { debuglog } from 'util'
import { EventEmitter } from 'events'

import { lookup, Visitor } from './internal/common'
import { parsePacket, ResetPacket, NegotiationPacket, RegularPacket } from './internal/packet'
// import { QuicError } from './internal/error'
import {
  kID,
  kSocket,
  kState,
  kVersion,
  kServer,
} from './internal/symbol'
import {
  MaxReceivePacketSize,
  SocketAddress,
  SessionType,
  ConnectionID,
  isSupportedVersion,
} from './internal/protocol'

import { createSocket, Socket, AddressInfo } from './socket'
import { Session } from './session'

const debug = debuglog('quic')

export class ServerSession extends Session {
  [kServer]: Server
  constructor (id: ConnectionID, socket: Socket, server: Server) {
    super(id, SessionType.SERVER)
    this[kSocket] = socket
    this[kServer] = server
    this[kState].localPort = server.localPort
    this[kState].localAddress = server.localAddress
    this[kState].localFamily = server.localFamily
    this[kState].localAddr = new SocketAddress(server.address())
  }

  get server () {
    return this[kServer]
  }
}

export class ServerState {
  destroyed: boolean

  constructor () {
    this.destroyed = false
  }
}

//
// *************** Server ***************
//
export class Server extends EventEmitter {
  // Event: 'listening'
  // Event: 'connection'

  [kSocket]: Socket | null
  [kState]: ServerState
  localFamily: string
  localAddress: string
  localPort: number
  listening: boolean
  conns: Map<string, ServerSession>
  constructor () {
    super()
    this[kSocket] = null
    this.localFamily = ''
    this.localAddress = ''
    this.localPort = 0
    this.listening = false
    this.conns = new Map()
    this[kState] = new ServerState()
  }

  address (): AddressInfo {
    return { port: this.localPort, family: this.localFamily, address: this.localAddress }
  }

  async listen (port: number, address: string = 'localhost') {
    if (this[kSocket] != null) {
      throw new Error('Server listening')
    }

    const addr = await lookup(address)
    debug(`server listen: ${address}, ${port}`, addr)

    const socket = this[kSocket] = createSocket(addr.family)
    socket
      .on('error', (err) => this.emit('error', err))
      .on('close', () => serverOnClose(this))
      .on('message', (msg: Buffer, rinfo: AddressInfo) => serverOnMessage(this, socket, msg, rinfo))

    const res = new Promise((resolve, reject) => {
      socket.once('listening', () => {
        socket.removeListener('error', reject)

        const localAddr = socket.address()
        this.localFamily = localAddr.family
        this.localAddress = localAddr.address
        this.localPort = localAddr.port
        this.listening = true

        resolve()
        this.emit('listening')
      })
      socket.once('error', reject)
    })
    // Can't support cluster
    socket.bind({ port, address: addr.address, exclusive: true })
    return res
  }

  close (err: any) {
    if (this[kState].destroyed) {
      return
    }
    this[kState].destroyed = true
    for (const session of this.conns.values()) {
      session.close(err)
    }
    this.emit('close')
    return
  }

  getConnections () {
    return Promise.resolve(this.conns.size)
  }

  ref () {
    return
  }

  unref () {
    return
  }
}

function serverOnClose (server: Server) {
  server.emit('error', new Error('the underlying socket closed'))
  for (const session of server.conns.values()) {
    session.destroy(new Error('the underlying socket closed'))
  }
  if (!server[kState].destroyed) {
    server[kState].destroyed = true
    server.emit('close')
  }
}

function serverOnMessage (server: Server, socket: Socket, msg: Buffer, rinfo: AddressInfo) {
  debug(`server message: ${msg.length} bytes`, rinfo)
  if (msg.length === 0) {
    return
  }
  // The packet size should not exceed protocol.MaxReceivePacketSize bytes
  // If it does, we only read a truncated packet, which will then end up undecryptable
  if (msg.length > MaxReceivePacketSize) {
    debug(`receive too large data: ${msg.length} bytes`)
    // msg = msg.slice(0, MaxReceivePacketSize)
  }

  const senderAddr = new SocketAddress(rinfo)
  const rcvTime = Date.now()

  const bufv = Visitor.wrap(msg)
  let packet = null
  try {
    packet = parsePacket(bufv, SessionType.CLIENT, '')
  } catch (err) {
    debug(`parsing packet error: ${err.message}`)
    // drop this packet if we can't parse the Public Header
    return
  }

  const connectionID = packet.connectionID.valueOf()
  let session = server.conns.get(connectionID)
  const newSession = session == null
  if (session == null) {
    session = new ServerSession(packet.connectionID, socket, server)
    server.conns.set(connectionID, session)
  } else if (session.destroyed) {
    // Late packet for closed session
    return
  }

  if (packet.isReset()) {
    if (newSession) {
      server.conns.delete(connectionID)
      return
    }
    // check if the remote address and the connection ID match
    // otherwise this might be an attacker trying to inject a PUBLIC_RESET to kill the connection
    const remoteAddr = session[kState].remoteAddr
    if (remoteAddr !== null && !remoteAddr.equals(senderAddr)) {
      debug(`Received a spoofed Public Reset. Ignoring.`)
      return
    }

    const packetNumber = (packet as ResetPacket).packetNumber
    session._closeRemote(new Error(`Received Public Reset, rejected packet number: ${packetNumber}.`))
    return
  }

  // update the remote address, even if unpacking failed for any other reason than a decryption error
  session[kState].remotePort = senderAddr.port
  session[kState].remoteAddress = senderAddr.address
  session[kState].remoteFamily = senderAddr.family
  session[kState].remoteAddr = senderAddr

  if (newSession) {
    server.emit('session', session)
  }

  if (packet.isNegotiation()) {
    debug(`Received a unexpect Negotiation packet. Ignoring.`)
    return
  }

  if (!session[kState].versionNegotiated) {
    const version = (packet as RegularPacket).version
    if (version !== '') {
      if (!isSupportedVersion(version)) {
        const negotiationPacket = NegotiationPacket.fromConnectionID(session[kID])
        session._sendPacket(negotiationPacket, (err) => {
          if (err != null && session != null) {
            session._closeRemote(err)
          }
        })
        return
      }
      session[kVersion] = version
    }
    session[kState].versionNegotiated = true
  }

  session[kState].bytesRead += msg.length
  session._handleRegularPacket(packet as RegularPacket, rcvTime, bufv)
}
