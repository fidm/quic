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

  _onPacket (packet) {}

  _sendPacket (packet) {
    return new Promise((resolve, reject) => {
      let buf = packet.toBuffer()
      if (!this._udp) return reject(new Error('UDP not connect'))
      this._udp.send(buf, 0, buf.length, this.remotePort, this.remoteAddress, (err) => {
        if (err != null) reject(err)
        else resolve()
      })
    })
  }

  openStream () {}
  close () {}
  destroy () {}
  address () {
    return {port: this.localPort, family: this.localFamily, address: this.localAddress}
  }
  ref () {}
  unref () {}
}

exports.Connection = Connection
