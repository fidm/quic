'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

import { createSocket as createUDP, Socket as UDPSocket } from 'dgram'
import {
  kState,
} from './internal/symbol'
import { Packet } from './internal/packet'
import { BufferVisitor, Visitor } from './internal/common'

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
  constructor () {
    this.exclusive = true
    this.destroyed = false
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
    return callback(new Error('packet size too large!'))
  }

  let bufv = bufferPool.shift()
  if (bufv == null) {
    bufv = Visitor.wrap(Buffer.alloc(1500)) // MTU
  }
  bufv.v.reset(0, 0)
  packet.writeTo(bufv)
  socket.send(bufv.slice(0, bufv.v.end), remotePort, remoteAddr, (err: any) => {
    bufferPool.push(bufv as BufferVisitor)
    callback(err)
  })
}
