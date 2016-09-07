'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const dgram = require('dgram')
const EventEmitter = require('events')
// const connection = require('./connection')

class QuicServer extends EventEmitter {
  constructor (options) {
    super()
    this.socket = dgram.createSocket(options)
  }

  address () {}

  close () {}

  getConnections () {}

  listen (options) {}

  get listening () {}

  ref () {}

  unref () {}
}

module.exports = QuicServer
