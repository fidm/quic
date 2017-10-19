'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const { createSocket } = require('dgram')
const { ConnectionID } = require('./protocol')
const { lookup } = require('./common')
const { ClientSession } = require('./session')

const kSocket = Symbol('socket')

// Event: 'connect'

class Client extends ClientSession {
  constructor () {
    super()

    this.id = ConnectionID.random()
  }

  async connect (port, address) {
    if (this[kSocket]) throw new Error('Client connected')

    let addr = await lookup(address || 'localhost')
    this.remotePort = port
    this.remoteAddress = addr.address
    this.remoteFamily = 'IPv' + addr.family

    this[kSocket] = createSocket(this.remoteFamily === 'IPv6' ? 'udp6' : 'udp4')
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
        this.emit('connect')
        resolve()
      })
      this[kSocket].once('error', reject)
    })
    this[kSocket].bind({exclusive: true})
    return res
  }
}

function onMessage (msg, rinfo) {
  // ...
}

function onClose () {

}

exports.Client = Client
