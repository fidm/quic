'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const dgram = require('dgram')
const EventEmitter = require('events')
// const connection = require('./connection')

class QuicClient extends EventEmitter {
  constructor (options) {
    super()
    this.socket = dgram.createSocket(options)
  }

  address () {}

  connect (options) {}

  get connecting () {}

  destroy () {}

  end () {}

  ref () {}

  send (data) {}

  unref () {}
}

module.exports = QuicClient
