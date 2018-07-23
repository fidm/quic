'use strict'
// **Github:** https://github.com/fidm/quic
//
// **License:** MIT

import { debuglog } from 'util'
import { MaxReceivePacketSize, MaxPacketSizeIPv4, MaxPacketSizeIPv6 } from './internal/constant'
import { dnsLookup, BufferVisitor } from './internal/common'
import { QuicError, QUICError } from './internal/error'
import { parsePacket, NegotiationPacket, RegularPacket } from './internal/packet'
import {
  FamilyType,
  ConnectionID,
  SocketAddress,
  SessionType,
  getVersion,
  chooseVersion,
} from './internal/protocol'
import {
  kHS,
  kSocket,
  kState,
  kVersion,
  kClientState,
  kIntervalCheck,
  kUnackedPackets,
} from './internal/symbol'

import { createSocket, AddressInfo, Socket } from './socket'
import { ClientHandShake } from './handshake'
import { Session } from './session'
import { Stream } from './stream'

const debug = debuglog('quic')

export declare interface Client {
  addListener (event: "error", listener: (err: Error) => void): this
  addListener (event: "goaway", listener: (err: QUICError) => void): this
  addListener (event: "close", listener: (err?: Error) => void): this
  addListener (event: "timeout" | "connect", listener: () => void): this
  addListener (event: "stream", listener: (stream: Stream) => void): this
  addListener (event: "version", listener: (ver: string) => void): this

  emit (event: "error", err: Error): boolean
  emit (event: "goaway", err: QUICError): boolean
  emit (event: "close", err?: Error): boolean
  emit (event: "timeout" | "connect"): boolean
  emit (event: "stream", stream: Stream): boolean
  emit (event: "version", ver: string): boolean

  on (event: "error", listener: (err: Error) => void): this
  on (event: "goaway", listener: (err: QUICError) => void): this
  on (event: "close", listener: (err?: Error) => void): this
  on (event: "timeout" | "connect", listener: () => void): this
  on (event: "stream", listener: (stream: Stream) => void): this
  on (event: "version", listener: (ver: string) => void): this

  once (event: "error", listener: (err: Error) => void): this
  once (event: "goaway", listener: (err: QUICError) => void): this
  once (event: "close", listener: (err?: Error) => void): this
  once (event: "timeout" | "connect", listener: () => void): this
  once (event: "stream", listener: (stream: Stream) => void): this
  once (event: "version", listener: (ver: string) => void): this
}

//
// *************** Client ***************
//
export class Client extends Session {
  [kClientState]: ClientState
  [kHS]: ClientHandShake
  constructor () {
    super(ConnectionID.random(), SessionType.CLIENT)
    this[kVersion] = getVersion()
    this[kHS] = new ClientHandShake(this)
    this[kClientState] = new ClientState()
    this[kIntervalCheck] = setInterval(() => {
      const time = Date.now()
      // client session idle timeout
      const sessionActivityTime = this[kState].lastNetworkActivityTime || this[kState].startTime
      if (time - sessionActivityTime > this[kState].idleTimeout) {
        this.emit('timeout')
        this.close(QuicError.fromError(QuicError.QUIC_NETWORK_IDLE_TIMEOUT))
        return
      }
      // other session check
      this._intervalCheck(time)
    }, 512)
  }

  _resendPacketsForNegotiation () {
    const packets = this[kUnackedPackets].toArray()
    this[kUnackedPackets].reset()
    for (const packet of packets) {
      this._sendPacket(packet, (err: any) => {
        if (err != null && !this.destroyed) {
          this.destroy(err)
        }
      })
    }
  }

  setKeepAlive (enable: boolean, _initialDelay?: number) {
    this[kState].keepAlivePingSent = enable
    // initialDelay TODO
  }

  ref () {
    const socket = this[kSocket]
    if (socket == null) {
      throw new Error('Client not connect')
    }
    socket.ref()
  }

  unref () {
    const socket = this[kSocket]
    if (socket == null) {
      throw new Error('Client not connect')
    }
    socket.unref()
  }

  async spawn (port: number, address: string = 'localhost'): Promise<Client> {
    if (this[kState].destroyed) {
      throw new Error('Client destroyed')
    }

    const socket = this[kSocket]
    if (socket == null || socket[kState].destroyed) {
      throw new Error('the underlying socket destroyed')
    }
    const addr = await dnsLookup(address)
    debug(`client connect: %s, %d, %j`, address, port, addr)

    const client = new Client()
    socket[kState].conns.set(client.id, client)
    socket[kState].exclusive = false

    client[kSocket] = socket
    client[kState].localFamily = this[kState].localFamily
    client[kState].localAddress = this[kState].localAddress
    client[kState].localPort = this[kState].localPort
    client[kState].localAddr = new SocketAddress(socket.address() as AddressInfo)
    client[kState].remotePort = port
    client[kState].remoteAddress = addr.address
    client[kState].remoteFamily = 'IPv' + addr.family
    client[kState].remoteAddr =
      new SocketAddress({ port, address: addr.address, family: `IPv${addr.family}` })
    client[kState].maxPacketSize = this[kState].maxPacketSize

    await new Promise((resolve, reject) => {
      client[kHS].once('secureConnection', () => {
        client.removeListener('error', reject)
        resolve()
      })
      client.once('error', reject)
      client[kHS].setup()
    })
    return client
  }

  async connect (port: number, address: string = 'localhost'): Promise<void> {
    if (this[kState].destroyed) {
      throw new Error('Client destroyed')
    }
    if (this[kSocket] != null) {
      throw new Error('Client connecting duplicated')
    }

    const addr = await dnsLookup(address)

    debug(`client connect: %s, %d, %j`, address, port, addr)
    this[kState].remotePort = port
    this[kState].remoteAddress = addr.address
    this[kState].remoteFamily = 'IPv' + addr.family
    this[kState].remoteAddr = new SocketAddress({ port, address: addr.address, family: `IPv${addr.family}` })
    this[kState].maxPacketSize =
      this[kState].localFamily === FamilyType.IPv6 ? MaxPacketSizeIPv6 : MaxPacketSizeIPv4

    const socket = this[kSocket] = createSocket<Client>(addr.family)
    socket[kState].conns.set(this.id, this)
    socket
      .on('error', (err) => this.emit('error', err))
      .on('close', () => this.destroy(new Error('the underlying socket closed')))
      .on('message', socketOnMessage)

    const res = new Promise((resolve, reject) => {
      socket.once('listening', () => {
        socket.removeListener('error', reject)

        const localAddr = socket.address() as AddressInfo
        this[kState].localFamily = localAddr.family
        this[kState].localAddress = localAddr.address
        this[kState].localPort = localAddr.port
        this[kState].localAddr = new SocketAddress(localAddr)

        this[kHS].once('secureConnection', () => {
          this.removeListener('error', reject)

          process.nextTick(() => this.emit('connect'))
          resolve()
        })
        this[kHS].setup()
      })
      this.once('error', reject)
      socket.once('error', reject)
    })
    socket.bind({ exclusive: true, port: 0 })
    await res
  }
}

export class ClientState {
  hostname: string
  receivedNegotiationPacket: boolean
  constructor () {
    this.hostname = ''
    this.receivedNegotiationPacket = false
  }
}

function socketOnMessage (this: Socket<Client>, msg: Buffer, rinfo: AddressInfo) {
  if (msg.length === 0 || this[kState].destroyed) {
    return
  }
  // The packet size should not exceed protocol.MaxReceivePacketSize bytes
  // If it does, we only read a truncated packet, which will then end up undecryptable
  if (msg.length > MaxReceivePacketSize) {
    debug(`client message - receive too large data: %d bytes`, msg.length)
    // msg = msg.slice(0, MaxReceivePacketSize)
  }

  const senderAddr = new SocketAddress(rinfo)
  const rcvTime = Date.now()

  const bufv = new BufferVisitor(msg)
  let packet = null
  try {
    packet = parsePacket(bufv, SessionType.SERVER)
  } catch (err) {
    debug(`client message - parsing packet error: %o`, err)
    // drop this packet if we can't parse the Public Header
    return
  }

  const connectionID = packet.connectionID.valueOf()
  const client = this[kState].conns.get(connectionID)
  if (client == null) {
    // reject packets with the wrong connection ID
    debug(`client message - received a spoofed packet with wrong ID: %s`, connectionID)
    return
  } else if (client.destroyed) {
    // Late packet for closed session
    return
  }

  if (packet.isReset()) {
    // check if the remote address and the connection ID match
    // otherwise this might be an attacker trying to inject a PUBLIC_RESET to kill the connection
    const remoteAddr = client[kState].remoteAddr
    if (remoteAddr == null || !remoteAddr.equals(senderAddr)) {
      debug(`session %s - received a spoofed Public Reset: %j`, client.id, senderAddr)
      return
    }

    debug(`session %s - Public Reset, rejected packet number: %j`, client.id, packet)
    client.destroy(QuicError.fromError(QuicError.QUIC_PUBLIC_RESET))
    return
  }

  if (packet.isNegotiation()) {
    // ignore delayed / duplicated version negotiation packets
    if (client[kClientState].receivedNegotiationPacket || client[kState].versionNegotiated) {
      return
    }

    const versions = (packet as NegotiationPacket).versions
    if (client[kVersion] !== '' && versions.includes(client[kVersion])) {
      // the version negotiation packet contains the version that we offered
      // this might be a packet sent by an attacker (or by a terribly broken server implementation)
      // ignore it
      return
    }

    const newVersion = chooseVersion(versions)
    client[kClientState].receivedNegotiationPacket = true
    debug(`session %s - received Public Negotiation: %s`, client.id, newVersion)
    if (newVersion !== '') {
      // switch to negotiated version
      client[kVersion] = newVersion
      client._resendPacketsForNegotiation()
    } else {
      client.destroy(QuicError.fromError(QuicError.QUIC_INVALID_VERSION))
    }

    return
  }

  // this is the first packet after the client sent a packet with the VersionFlag set
  // if the server doesn't send a version negotiation packet, it supports the suggested version
  if (!client[kState].versionNegotiated) {
    client[kState].versionNegotiated = true
    client.emit('version', client.version)
  }

  client[kState].bytesRead += msg.length
  try {
    client._handleRegularPacket(packet as RegularPacket, rcvTime, bufv)
  } catch (err) {
    debug(`CLIENT session %s - handle RegularPacket error: %o`, client.id, err)
    client.destroy(QuicError.fromError(err))
  }
}
