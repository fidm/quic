'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

import { debuglog } from 'util'
import { lookup, Visitor } from './internal/common'
import { QuicError } from './internal/error'
import { parsePacket, NegotiationPacket, RegularPacket } from './internal/packet'
import {
  ConnectionID,
  MaxReceivePacketSize,
  SocketAddress,
  SessionType,
  getVersion,
  chooseVersion,
} from './internal/protocol'
import {
  kID,
  kSocket,
  kState,
  kVersion,
  kClientState,
  kIntervalCheck,
  kUnackedPackets,
} from './internal/symbol'

import { createSocket, AddressInfo } from './socket'
import { Session } from './session'

const debug = debuglog('quic')

//
// *************** Client ***************
//
export class Client extends Session {
  [kClientState]: ClientState
  constructor () {
    super(ConnectionID.random(), SessionType.CLIENT)
    this[kVersion] = getVersion()
    this[kClientState] = new ClientState()
    this[kIntervalCheck] = setInterval(() => {
      const time = Date.now()
      // client session idle timeout
      if (time - this[kState].lastNetworkActivityTime > this[kState].idleTimeout) {
        this.emit('timeout')
        this.close(QuicError.fromError(QuicError.QUIC_NETWORK_IDLE_TIMEOUT))
        return
      }
      // other session check
      this._intervalCheck(time)
    }, 1024)
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

  async connect (port: number, address: string = 'localhost'): Promise<any> {
    if (this[kSocket] != null) {
      throw new Error('Client connecting duplicated')
    }
    if (this[kState].destroyed) {
      throw new Error('Client destroyed')
    }

    const addr = await lookup(address)

    debug(`client connect: %s, %d, %j`, address, port, addr)
    this[kState].remotePort = port
    this[kState].remoteAddress = addr.address
    this[kState].remoteFamily = 'IPv' + addr.family
    this[kState].remoteAddr = new SocketAddress({ port, address: addr.address, family: `IPv${addr.family}` })

    const socket = this[kSocket] = createSocket(addr.family)
    socket
      .on('error', (err) => this.emit('error', err))
      .on('close', () => this.destroy(new Error('the underlying socket closed')))
      .on('message', (msg, rinfo) => clientOnMessage(this, msg, rinfo))

    const res = new Promise((resolve, reject) => {
      socket.once('listening', () => {
        socket.removeListener('error', reject)

        const localAddr = socket.address()
        this[kState].localFamily = localAddr.family
        this[kState].localAddress = localAddr.address
        this[kState].localPort = localAddr.port
        this[kState].localAddr = new SocketAddress(localAddr)
        resolve()
        this.emit('connect')
      })
      socket.once('error', reject)
    })
    socket.bind({ exclusive: true, port: 0 })
    return res
  }
}

export class ClientState {
  receivedNegotiationPacket: boolean
  constructor () {
    this.receivedNegotiationPacket = false
  }
}

function clientOnMessage (client: Client, msg: Buffer, rinfo: AddressInfo) {
  if (msg.length === 0 || client.destroyed) {
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

  const bufv = Visitor.wrap(msg)
  let packet = null
  try {
    packet = parsePacket(bufv, SessionType.SERVER, client[kVersion])
  } catch (err) {
    debug(`session %s - parsing packet error: %o`, client.id, err)
    // drop this packet if we can't parse the Public Header
    return
  }
  // reject packets with the wrong connection ID
  if (!client[kID].equals(packet.connectionID)) {
    debug(`session %s - received a spoofed packet with wrong ID: %s`, client.id, packet.connectionID)
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
  client._handleRegularPacket(packet as RegularPacket, rcvTime, bufv)
}