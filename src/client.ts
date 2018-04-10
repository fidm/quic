'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

import { debuglog } from 'util'
import { lookup, Visitor } from './internal/common'
import { parsePacket, ResetPacket, NegotiationPacket, RegularPacket } from './internal/packet'
import { QuicError } from './internal/error'
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
  }

  async connect (port: number, address: string = 'localhost'): Promise<any> {
    if (this[kSocket] != null) {
      throw new Error('Client connecting duplicated')
    }

    const addr = await lookup(address)

    debug(`client connect: ${address}, ${port}`, addr)
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
  debug(`client message: session ${client.id}, ${msg.length} bytes`, rinfo)
  if (msg.length === 0 || client.destroyed) {
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
    packet = parsePacket(bufv, SessionType.SERVER, client[kVersion])
  } catch (err) {
    debug(`session ${client.id}: parsing packet error: ${err.message}`, JSON.stringify(rinfo))
    // drop this packet if we can't parse the Public Header
    return
  }
  // reject packets with the wrong connection ID
  if (!client[kID].equals(packet.connectionID)) {
    debug(`received a spoofed packet with wrong connection ID. Ignoring.`)
    return
  }

  if (packet.isReset()) {
    // check if the remote address and the connection ID match
    // otherwise this might be an attacker trying to inject a PUBLIC_RESET to kill the connection
    const remoteAddr = client[kState].remoteAddr
    if (remoteAddr == null || !remoteAddr.equals(senderAddr)) {
      debug(`received a spoofed Public Reset. Ignoring.`)
      return
    }

    const packetNumber = (packet as ResetPacket).packetNumber
    client._closeRemote(new Error(`Received Public Reset, rejected packet number: ${packetNumber}.`))
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
    if (newVersion !== '') {
      // switch to negotiated version
      client[kVersion] = newVersion
      // TODO: resend all packets using this version
    } else {
      client.close(new QuicError('QUIC_INVALID_VERSION'))
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
