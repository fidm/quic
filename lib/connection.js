'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const EventEmitter = require('events')

// Event: 'timeout'
// Event: 'close'
// Event: 'error'
// Event: 'stream'

class Connection extends EventEmitter {
  constructor () {
    super()

    this.id = null
    this._udp = null
    this.bytesRead = 0
    this.bytesWritten = 0
    this.localFamily = ''
    this.localAddress = ''
    this.localPort = 0
    this.remoteFamily = ''
    this.remoteAddress = ''
    this.remotePort = 0
    this.isServer = false
    this.streams = new Map()
  }

  _writePacket (packet) {}
  close () {}
  destroy () {}
  address () {
    return {port: this.localPort, family: this.localFamily, address: this.localAddress}
  }
  ref () {}
  unref () {}
}

exports.Connection = Connection
