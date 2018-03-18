'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

import { createSocket, AddressInfo } from 'dgram'

import { lookup, Visitor } from './internal/common'
import { parsePacket, ResetPacket, NegotiationPacket, RegularPacket } from './internal/packet'
import { QuicError } from './internal/error'
import {
  ConnectionID,
  MaxReceivePacketSize,
  SocketAddress,
  SessionType,
  getVersion,
  chooseVersion
} from './internal/protocol'
import {
  kID,
  kSocket,
  kState,
  kVersion,
  kClientState
} from './internal/symbol'

import { Session } from './session'
import { debuglog } from 'util'

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

  async connect (port: number, address: string): Promise<any> {
    if (this[kSocket]) throw new Error('Client connecting duplicated')

    let addr = await lookup(address || 'localhost')

    debug(`client connect: ${address || 'localhost'}, ${port}`, addr)
    this[kState].remotePort = port
    this[kState].remoteAddress = addr.address
    this[kState].remoteFamily = 'IPv' + addr.family
    this[kState].remoteAddr = new SocketAddress({ port: port, address: addr.address, family: `IPv${addr.family}` })

    const socket = this[kSocket] = createSocket(addr.family === 4 ? 'udp4' : 'udp6')
    socket
      .on('error', (err) => this.emit('error', err))
      .on('close', () => clientOnClose(this))
      .on('message', (msg, rinfo) => clientOnMessage(this, msg, rinfo))

    let res = new Promise((resolve, reject) => {
      socket.once('listening', () => {
        socket.removeListener('error', reject)

        let addr = socket.address()
        this[kState].localFamily = addr.family
        this[kState].localAddress = addr.address
        this[kState].localPort = addr.port
        this[kState].localAddr = new SocketAddress(addr)
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
  if (!msg.length) {
    return
  }
  // The packet size should not exceed protocol.MaxReceivePacketSize bytes
  // If it does, we only read a truncated packet, which will then end up undecryptable
  if (msg.length > MaxReceivePacketSize) {
    debug(`receive too large data: ${msg.length} bytes`)
    msg = msg.slice(0, MaxReceivePacketSize)
  }

  let senderAddr = new SocketAddress(rinfo)
  let rcvTime = Date.now()

  let bufv = Visitor.wrap(msg)
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
    let remoteAddr = client[kState].remoteAddr
    if (!remoteAddr || !remoteAddr.equals(senderAddr)) {
      debug(`received a spoofed Public Reset. Ignoring.`)
      return
    }

    let packetNumber = (packet as ResetPacket).packetNumber
    client._closeRemote(new Error(`Received Public Reset, rejected packet number: ${packetNumber}.`))
    return
  }

  if (packet.isNegotiation()) {
    // ignore delayed / duplicated version negotiation packets
    if (client[kClientState].receivedNegotiationPacket || client[kState].versionNegotiated) {
      return
    }

    let versions = (packet as NegotiationPacket).versions
    if (client[kVersion] && versions.includes(client[kVersion])) {
      // the version negotiation packet contains the version that we offered
      // this might be a packet sent by an attacker (or by a terribly broken server implementation)
      // ignore it
      return
    }

    let newVersion = chooseVersion(versions)
    client[kClientState].receivedNegotiationPacket = true
    if (newVersion) {
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

function clientOnClose (_session: Client) {

}
