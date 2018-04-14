'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

// NODE_DEBUG=quic,quic:session,quic:stream node -r ts-node/register example/server.js
const ilog = require('ilog')
const {
  Server
} = require('../src')

const server = new Server()

server
  .on('error', ilog.error)
  .on('session', (session) => {
    ilog.info(`new session - ${session.id}`)

    session
      .on('error', ilog.error)
      .on('stream', (stream) => {
        ilog.info(`new stream - ${stream.id}`)

        stream
          .on('error', ilog.error)
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
