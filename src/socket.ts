'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

import { createSocket as createUDP, Socket as UDPSocket } from 'dgram'
import {
  kState,
} from './internal/symbol'
import { Packet } from './internal/packet'
import { QuicError } from './internal/error'
import { BufferVisitor, Visitor } from './internal/common'
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
  })
  Object.assign(socket, { [kState]: state })
  return socket as Socket
}

const bufferPool: BufferVisitor[] = []
export function sendPacket (socket: Socket, packet: Packet, remotePort: number, remoteAddr: string, callback: (err: any) => void) {
  const byteLen = packet.byteLen()
  if (byteLen > 1500) {
    return callback(new QuicError('packet size too large!'))
  }
  if (socket[kState].destroyed) {
    return callback(new QuicError('socket destroyed!'))
  }

  let bufv = bufferPool.shift()
  if (bufv == null) {
    bufv = Visitor.wrap(Buffer.alloc(1500)) // MTU
  }
  bufv.v.reset(0, 0)
  packet.writeTo(bufv)
  socket.send(bufv, 0, bufv.v.end, remotePort, remoteAddr, (err: any) => {
    bufferPool.push(bufv as BufferVisitor)
    callback(QuicError.checkAny(err))
  })
}
