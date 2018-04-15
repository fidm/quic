'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

import { createSocket as createUDP, Socket as UDPSocket } from 'dgram'
import {
  kState,
} from './internal/symbol'

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
