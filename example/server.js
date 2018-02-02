'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

// node example/server.js
const ilog = require('ilog')
const {
  QUICServer
} = require('..')

const server = new QUICServer()

server
  .on('error', ilog.error)
  .on('session', (session) => {
    ilog.info(`session: ${session.id}`)

    session
      .on('ping', () => {
        ilog.info('ping')
      })
      .on('stream', (stream) => {
        ilog.info(`stream: ${stream.id}`)

        stream.on('data', (data) => {
          ilog.info(data.toString())
          stream.write(Buffer.from(`ECHO: ${data.toString()}`))
        })
      })
  })

server.listen(2345)
  .then(() => ilog.info(`server listening: ${JSON.stringify(server.address())}`))
  .catch(ilog.error)
