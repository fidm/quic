'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const { createSocket } = require('dgram')
const EventEmitter = require('events')
const { lookup } = require('./common')

// Event: 'listening'
// Event: 'connection'

class Server extends EventEmitter {
  constructor () {
    super()
    this._udp = null
    this.localFamily = ''
    this.localAddress = ''
    this.localPort = 0
    this.listening = false
    this.conns = new Map()
  }

  address () {
    return {port: this.localPort, family: this.localFamily, address: this.localAddress}
  }

  async listen (port, address) {
    if (this._udp) throw new Error('Server listening')

    let type = 'upd4'
    if (address) {
      let addr = await lookup(address || 'localhost')
      if (addr.family === 6) type = 'upd6'
    }

    this._udp = createSocket(type)
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
        this.emit('listening')
        resolve()
      })
      this._udp.once('error', reject)
    })
    // Can't support cluster
    this._udp.bind({port: port, address: address, exclusive: true})
    return res
  }

  _onmessage (msg, rinfo) {}
  _onclose () {}

  close () {}
  getConnections () {
    return Promise.resolve(this.conns.size)
  }
  ref () {}
  unref () {}
}

exports.Server = Server
