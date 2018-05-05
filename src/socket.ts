'use strict'
// **Github:** https://github.com/fidm/quic
//
// **License:** MIT

import { createSocket as createUDP, Socket as UDPSocket } from 'dgram'
import {
  kState,
} from './internal/symbol'
import { Packet } from './internal/packet'
import { QuicError } from './internal/error'
import { BufferVisitor } from './internal/common'
import { MaxReceivePacketSize } from './internal/constant'
import { Client } from './client';

export interface AddressInfo {
  address: string;
  family: string;
  port: number;
}

// BufferVisitor is a buffer wrapped by Visitor
export interface Socket extends UDPSocket {
  [kState]: SocketState
}

export class SocketState {
  exclusive: boolean // is shared between all sessions or not
  destroyed: boolean
  conns: Map<string, Client>
  constructor () {
    this.exclusive = true
    this.destroyed = false
    this.conns = new Map()
  }
}

export function createSocket (family: number): Socket {
  const socket = createUDP(family === 6 ? 'udp6' : 'udp4')
  const state = new SocketState()

  socket.once('close', () => {
    state.destroyed = true
    socket.removeAllListeners()
  })
  Object.assign(socket, { [kState]: state })
  return socket as Socket
}

const bufferPool: BufferVisitor[] = []
export function sendPacket (socket: Socket, packet: Packet, remotePort: number, remoteAddr: string, callback: (err: any) => void) {
  const byteLen = packet.byteLen()
  if (byteLen > MaxReceivePacketSize) {
    return callback(new QuicError('packet size too large!'))
  }
  if (socket[kState].destroyed) {
    return callback(new QuicError('socket destroyed!'))
  }

  let bufv = bufferPool.shift()
  if (bufv == null) {
    bufv = new BufferVisitor(Buffer.alloc(MaxReceivePacketSize))
  } else {
    bufv.reset()
  }
  packet.writeTo(bufv)
  socket.send(bufv.buf, 0, bufv.end, remotePort, remoteAddr, (err: any) => {
    packet.sentTime = Date.now()
    bufferPool.push(bufv as BufferVisitor)
    callback(QuicError.checkAny(err))
  })
}
