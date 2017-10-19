'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const { createSocket } = require('dgram')
const EventEmitter = require('events')
const { lookup } = require('./common')
const { ServerSession } = require('./session')

const kSocket = Symbol('socket')

class Server extends EventEmitter {
  // Event: 'listening'
  // Event: 'connection'

  constructor () {
    super()
    this[kSocket] = null
    this.localFamily = ''
    this.localAddress = ''
    this.localPort = 0
    this.listening = false
    this.conns = new Map()
  }

  address () {
    return { port: this.localPort, family: this.localFamily, address: this.localAddress }
  }

  async listen (port, address) {
    if (this[kSocket]) throw new Error('Server listening')

    let type = 'upd4'
    if (address) {
      let addr = await lookup(address || 'localhost')
      if (addr.family === 6) type = 'upd6'
    }

    this[kSocket] = createSocket(type)
    this[kSocket].server = this
    this[kSocket]
      .on('error', (err) => this.emit('error', err))
      .on('close', onClose)
      .on('message', onMessage)

    let res = new Promise((resolve, reject) => {
      this[kSocket].once('listening', () => {
        this[kSocket].removeListener('error', reject)

        let addr = this[kSocket].address()
        this.localFamily = addr.family
        this.localAddress = addr.address
        this.localPort = addr.port
        this.emit('listening')
        resolve()
      })
      this[kSocket].once('error', reject)
    })
    // Can't support cluster
    this[kSocket].bind({port: port, address: address, exclusive: true})
    return res
  }

  close () {}

  getConnections () {
    return Promise.resolve(this.conns.size)
  }

  ref () {}

  unref () {}
}

function onMessage (msg, rinfo) {
  // ...
  const session = new ServerSession(this, this.server)
  this.server.emit('session', session)
}

function onClose () {

}

exports.Server = Server
