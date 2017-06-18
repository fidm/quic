'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const { createSocket } = require('dgram')
const { Connection } = require('./connection')
const { ConnectionID } = require('./protocol')
const { lookup } = require('./common')

// Event: 'connect'

class Client extends Connection {
  constructor () {
    super()

    this.id = ConnectionID.random()
    this.isServer = false
  }

  async connect (port, address) {
    if (this._udp) throw new Error('Client connected')

    let addr = await lookup(address || 'localhost')
    this.remotePort = port
    this.remoteAddress = addr.address
    this.remoteFamily = 'IPv' + addr.family

    this._udp = createSocket(this.remoteFamily === 'IPv6' ? 'udp6' : 'udp4')
    this._udp
      .on('error', (err) => this.emit('error', err))
      .on('close', () => this._onclose())
      .on('message', (msg, rinfo) => this._onmessage(msg, rinfo))

    let res = new Promise((resolve, reject) => {
      this._udp.once('listening', () => {
        this._udp.removeListener('error', reject)

        let addr = this._udp.address()
        this.localFamily = addr.family
        this.localAddress = addr.address
        this.localPort = addr.port
        this.emit('connect')
        resolve()
      })
      this._udp.once('error', reject)
    })
    this._udp.bind({exclusive: true})
    return res
  }

  _onmessage (msg, rinfo) {}
  _onclose () {}
}

exports.Client = Client
