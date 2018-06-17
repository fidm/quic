'use strict'
// **Github:** https://github.com/fidm/quic
//
// **License:** MIT

import { debuglog } from 'util'
import { EventEmitter } from 'events'

import { MaxReceivePacketSize, MaxPacketSizeIPv4, MaxPacketSizeIPv6 } from './internal/constant'
import { dnsLookup, BufferVisitor } from './internal/common'
import { QuicError } from './internal/error'
import { parsePacket, NegotiationPacket, RegularPacket } from './internal/packet'
import {
  kID,
  kHS,
  kConns,
  kSocket,
  kState,
  kVersion,
  kServer,
  kIntervalCheck,
} from './internal/symbol'
import {
  FamilyType,
  SocketAddress,
  SessionType,
  ConnectionID,
  isSupportedVersion,
} from './internal/protocol'
import { SourceToken } from './internal/crypto'

import { createSocket, Socket, AddressInfo } from './socket'
import { ServerHandShake, ServerConfig } from './handshake'
import { Session } from './session'

const debug = debuglog('quic')

export class ServerSession extends Session {
  [kHS]: ServerHandShake
  [kServer]: Server
  constructor (id: ConnectionID, socket: Socket<ServerSession>, server: Server) {
    super(id, SessionType.SERVER)
    this[kSocket] = socket
    this[kServer] = server
    this[kHS] = new ServerHandShake(this, server[kState].sourceToken, server[kState].scfg)
    this[kState].localPort = server.localPort
    this[kState].localAddress = server.localAddress
    this[kState].localFamily = server.localFamily
    this[kState].localAddr = new SocketAddress(server.address())
    this[kState].maxPacketSize =
      server.localFamily === FamilyType.IPv6 ? MaxPacketSizeIPv6 : MaxPacketSizeIPv4
  }

  get server () {
    return this[kServer]
  }
}

export class ServerState {
  destroyed: boolean
  scfg: ServerConfig
  sourceToken: SourceToken

  constructor () {
    this.destroyed = false
    this.scfg = new ServerConfig(null)
    this.sourceToken = new SourceToken()
  }
}

export declare interface Server {
  addListener (event: "error", listener: (err: Error) => void): this
  addListener (event: "close", listener: (err?: Error) => void): this
  addListener (event: "listening", listener: () => void): this
  addListener (event: "session", listener: (session: Session) => void): this

  emit (event: "error", err: Error): boolean
  emit (event: "close", err?: Error): boolean
  emit (event: "listening"): boolean
  emit (event: "session", session: Session): boolean

  on (event: "error", listener: (err: Error) => void): this
  on (event: "close", listener: (err?: Error) => void): this
  on (event: "listening", listener: () => void): this
  on (event: "session", listener: (session: Session) => void): this

  once (event: "error", listener: (err: Error) => void): this
  once (event: "close", listener: (err?: Error) => void): this
  once (event: "listening", listener: () => void): this
  once (event: "session", listener: (session: Session) => void): this
}

//
// *************** Server ***************
//
export class Server extends EventEmitter {
  [kSocket]: Socket<ServerSession> | null
  [kState]: ServerState
  localFamily: string
  localAddress: string
  localPort: number
  listening: boolean
  private [kConns]: Map<string, ServerSession>
  private [kIntervalCheck]: NodeJS.Timer
  constructor () {
    super()
    this[kSocket] = null
    this.localFamily = ''
    this.localAddress = ''
    this.localPort = 0
    this.listening = false
    this[kConns] = new Map()
    this[kState] = new ServerState()
    this[kIntervalCheck] = setInterval(() => {
      const time = Date.now()
      this._intervalCheck(time)
    }, 1024)
  }

  address (): AddressInfo {
    return { port: this.localPort, family: this.localFamily, address: this.localAddress }
  }

  async listen (port: number, address: string = 'localhost') {
    if (this[kSocket] != null) {
      throw new Error('Server listening')
    }

    const addr = await dnsLookup(address)
    debug(`server listen: ${address}, ${port}`, addr)

    const socket = this[kSocket] = createSocket<ServerSession>(addr.family)
    socket[kState].exclusive = false // socket is shared between all sessions
    socket
      .on('error', (err) => this.emit('error', err))
      .on('close', () => serverOnClose(this))
      .on('message', (msg: Buffer, rinfo: AddressInfo) => serverOnMessage(this, socket, msg, rinfo))

    const res = new Promise((resolve, reject) => {
      socket.once('listening', () => {
        socket.removeListener('error', reject)

        const localAddr = socket.address() as AddressInfo
        this.localFamily = localAddr.family
        this.localAddress = localAddr.address
        this.localPort = localAddr.port
        this.listening = true

        process.nextTick(() => this.emit('listening'))
        resolve()
      })
      socket.once('error', reject)
    })
    // Can't support cluster
    socket.bind({ port, address: addr.address, exclusive: true })
    return res
  }

  _intervalCheck (time: number) {
    for (const session of this[kConns].values()) {
      // server session idle timeout
      if (time - session[kState].lastNetworkActivityTime > session[kState].idleTimeout) {
        // When a server decides to terminate an idle connection,
        // it should not notify the client to avoid waking up the radio on mobile devices.
        if (!session.destroyed) {
          session.emit('timeout')
          session.destroy(QuicError.fromError(QuicError.QUIC_NETWORK_IDLE_TIMEOUT))
        }
        this[kConns].delete(session.id)
        return
      }
      // other session check
      session._intervalCheck(time)
    }
    return
  }

  shutdown (_timeout: number): Promise<void> {
    return Promise.reject('TODO')
  }

  async close (err?: any) {
    if (this[kState].destroyed) {
      return
    }
    this[kState].destroyed = true
    for (const session of this[kConns].values()) {
      await session.close(err)
    }
    const timer = this[kIntervalCheck]
    if (timer != null) {
      clearInterval(timer)
    }
    const socket = this[kSocket]
    if (socket != null && !socket[kState].destroyed) {
      socket.close()
      socket[kState].destroyed = true
    }
    process.nextTick(() => this.emit('close'))
  }

  getConnections () {
    return Promise.resolve(this[kConns].size) // TODO
  }

  ref () {
    const socket = this[kSocket]
    if (socket == null) {
      throw new Error('Server not listen')
    }
    socket.ref()
  }

  unref () {
    const socket = this[kSocket]
    if (socket == null) {
      throw new Error('Server not listen')
    }
    socket.unref()
  }
}

function serverOnClose (server: Server) {
  for (const session of server[kConns].values()) {
    session.destroy(new Error('the underlying socket closed'))
  }
  // server[kConns].clear()
  if (!server[kState].destroyed) {
    const timer = server[kIntervalCheck]
    if (timer != null) {
      clearInterval(timer)
    }
    server[kState].destroyed = true
    server.emit('close')
  }
}

function serverOnMessage (server: Server, socket: Socket<any>, msg: Buffer, rinfo: AddressInfo) {
  if (msg.length === 0 || server[kState].destroyed) {
    return
  }
  // The packet size should not exceed protocol.MaxReceivePacketSize bytes
  // If it does, we only read a truncated packet, which will then end up undecryptable
  if (msg.length > MaxReceivePacketSize) {
    debug(`server message - receive too large data: $d bytes`, msg.length)
    // msg = msg.slice(0, MaxReceivePacketSize)
  }

  const senderAddr = new SocketAddress(rinfo)
  const rcvTime = Date.now()

  const bufv = new BufferVisitor(msg)
  let packet = null
  try {
    packet = parsePacket(bufv, SessionType.CLIENT)
  } catch (err) {
    debug(`server message - parsing packet error: %o`, err)
    // drop this packet if we can't parse the Public Header
    return
  }

  if (packet.isNegotiation()) {
    debug(`server message - Received a unexpect Negotiation packet.`)
    return
  }

  const connectionID = packet.connectionID.valueOf()
  let session = server[kConns].get(connectionID)
  const newSession = session == null
  if (session == null) {
    if (packet.isReset()) {
      return
    }
    session = new ServerSession(packet.connectionID, socket, server)
    server[kConns].set(connectionID, session)
    debug(`server message - new session: %s`, connectionID)
  } else if (session.destroyed) {
    // Late packet for closed session
    return
  }

  if (packet.isReset()) {
    // check if the remote address and the connection ID match
    // otherwise this might be an attacker trying to inject a PUBLIC_RESET to kill the connection
    const remoteAddr = session[kState].remoteAddr
    if (remoteAddr !== null && !remoteAddr.equals(senderAddr)) {
      debug(`session %s - received a spoofed Public Reset: %j`, session.id, senderAddr)
      return
    }

    debug(`session %s - received a Public Reset: %j`, session.id, packet)
    session.destroy(QuicError.fromError(QuicError.QUIC_PUBLIC_RESET))
    return
  }

  // update the remote address, even if unpacking failed for any other reason than a decryption error
  session[kState].remotePort = senderAddr.port
  session[kState].remoteAddress = senderAddr.address
  session[kState].remoteFamily = senderAddr.family
  session[kState].remoteAddr = senderAddr

  const version = (packet as RegularPacket).version
  if (!session[kState].versionNegotiated) {
    if (!isSupportedVersion(version)) {
      const negotiationPacket = NegotiationPacket.fromConnectionID(session[kID])
      debug(`session %s - send Public Negotiation: %j`, session.id, negotiationPacket)
      session._sendPacket(negotiationPacket, (err) => {
        if (err != null && session != null) {
          session.close(err)
        }
      })
      return
    }
    session[kVersion] = version
    session[kState].versionNegotiated = true
  } else if (version !== '' && session[kVersion] !== version) {
    debug(`session %s - invalid version in RegularPacket: %s`, session.id, version)
    return
  }

  if (newSession) {
    server.emit('session', session)
    // session[kHS].once('secureConnection', () => server.emit('session', session))
  }

  session[kState].bytesRead += msg.length
  try {
    session._handleRegularPacket(packet as RegularPacket, rcvTime, bufv)
  } catch (err) {
    debug(`SERVER session %s - handle RegularPacket error: %o`, session.id, err)
    session.destroy(QuicError.fromError(err))
  }
}
