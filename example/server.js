'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

// node example/server.js
const ilog = require('ilog')
const {
  Server
} = require('../dist/index')

const server = new Server()

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

        stream
          .on('data', (data) => {
            // ilog.info(data.toString())
            stream.write(data)
          })
          .on('end', () => {
            ilog.info('server end')
            stream.end()
          })
          .on('finish', () => {
            ilog.info('server finish')
          })
      })
  })

server.listen(2345)
  .then(() => ilog.info(`server listening: ${JSON.stringify(server.address())}`))
  .catch(ilog.error)
