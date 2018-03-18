'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

// NODE_DEBUG=quic node example/server.js
const ilog = require('ilog')
const {
  Server
} = require('..')

const server = new Server()

server
  .on('error', ilog.error)
  .on('session', (session) => {
    ilog.info(`session: ${session.id}`)

    session
      .on('ping', () => {
        ilog.info('ping')
      })
      .on('error', (err) => {
        err.class = `session: ${session.id}`
        ilog.error(err)
      })
      .on('stream', (stream) => {
        ilog.info(`stream: ${stream.id}`)

        stream
          .on('error', (err) => {
            err.class = `stream: ${stream.id}`
            ilog.error(err)
          })
          .on('data', (data) => {
            stream.write(data)
          })
          .on('end', () => {
            ilog.info('stream end')
            stream.end()
          })
          .on('finish', () => {
            ilog.info('stream finish')
          })
      })
  })

server.listen(2345)
  .then(() => ilog.info(`server listening: ${JSON.stringify(server.address())}`))
  .catch(ilog.error)
