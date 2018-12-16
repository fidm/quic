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

export { AddressInfo } from 'net'

export enum SocketFamily {
    UDP6 = 6,
    UDP4 = 4,
}

export interface Socket<T> extends UDPSocket {
  [kState]: SocketState<T>
  sendPacket (packet: Packet, remotePort: number, remoteAddr: string, callback: (err: any) => void): void
}

export class SocketState<T> {
  exclusive: boolean // is shared between all sessions or not
  destroyed: boolean
  conns: Map<string, T>
  constructor () {
    this.exclusive = true
    this.destroyed = false
    this.conns = new Map()
  }
}

export function createSocket<T> (family: SocketFamily): Socket<T> {
  const socket = createUDP(family === SocketFamily.UDP6 ? 'udp6' : 'udp4')
  const state = new SocketState<T>()

  socket.once('close', () => {
    state.destroyed = true
    socket.removeAllListeners()
  })

  Object.assign(socket, {
    [kState]: state,
    sendPacket,
  })
  return socket as Socket<T>
}

const bufferPool: BufferVisitor[] = []

function sendPacket<T> (
  this: Socket<T>,
  packet: Packet,
  remotePort: number,
  remoteAddr: string,
  callback: (err: any) => void) {
  const byteLen = packet.byteLen()
  if (byteLen > MaxReceivePacketSize) {
    return callback(new QuicError('packet size too large!'))
  }
  if (this[kState].destroyed) {
    return callback(new QuicError('socket destroyed!'))
  }

  let bufv = bufferPool.shift()

  if (bufv == null) {
    bufv = new BufferVisitor(Buffer.alloc(MaxReceivePacketSize))
  } else {
    bufv.reset()
  }

  packet.writeTo(bufv)

  this.send(bufv.buf, 0, bufv.end, remotePort, remoteAddr, (err: any) => {
    packet.sentTime = Date.now()
    bufferPool.push(bufv as BufferVisitor)
    callback(QuicError.checkAny(err))
  })
}
