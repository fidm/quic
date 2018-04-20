'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

// node example/echo.js
// NODE_DEBUG=quic,quic:session,quic:stream node example/echo.js
require('ts-node/register')
const ilog = require('ilog')
const thunk = require('thunks').thunk
const {
  Server,
  Client
} = require('../src')

// ---------- Server ----------
const server = new Server()
server
  .on('error', (err) => ilog.error(Object.assign(err, { class: 'server error' })))
  .on('session', (session) => {
    // ilog.info(session)

    session
      .on('error', (err) => ilog.error(Object.assign(err, { class: 'server session error' })))
      .on('stream', (stream) => {
        // ilog.info(stream)

        stream
          .on('error', (err) => ilog.error(Object.assign(err, { class: 'server stream error' })))
          .on('data', (data) => {
            ilog.info(`server stream ${stream.id} data: ${data.toString()}`)
            stream.write(data)
          })
          .on('end', () => {
            ilog.info(`server stream ${stream.id} ended`)
            stream.end()
          })
          .on('finish', () => {
            ilog.info(`server stream ${stream.id} finished`)
          })
      })
  })

server.listen(2345)
  .then(() => ilog.info(Object.assign({ class: 'server listen' }, server.address())))
  .catch(ilog.error)

// ---------- Client ----------
const cli = new Client()
cli.on('error', (err) => ilog.error(Object.assign(err, { class: 'client error' })))

thunk(function * () {
  yield cli.connect(2345)
  yield cli.ping()

  const stream = cli.request()
  stream
    .on('error', (err) => ilog.error(Object.assign(err, { class: 'client stream error' })))
    .on('data', (data) => {
      ilog.info(`client stream ${stream.id} data: ${data.toString()}`)
    })
    .on('end', () => {
      ilog.info(`client stream ${stream.id} ended`)
      cli.close()
    })
    .on('finish', () => {
      ilog.info(`client stream ${stream.id} finished`)
    })

  yield (done) => stream.write('hello, QUIC', done)

  let i = 0
  while (i < 999) {
    yield thunk.delay(100)
    yield (done) => stream.write(`${i++}`, done)
  }

  yield (done) => stream.end(done)
  yield (done) => cli.once('close', done)
  process.exit(0)
})(ilog.error)
