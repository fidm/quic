'use strict'

// NODE_DEBUG=quic node example/client.js

const assert = require('assert')
const ilog = require('ilog')
const thunk = require('thunks').thunk

const {
  Client
} = require('..')

const cli = new Client()
cli.on('error', ilog.error)

thunk(function * () {
  yield cli.connect(2345)
  yield cli.ping()

  let stream = cli.request()
  let str = ''
  let i = 0
  while (i < 10000) {
    str += `${i}\n`
    i += 1
  }
  let list = []
  stream
    .on('error', (err) => {
      err.class = `stream: ${stream.id}`
      ilog.error(err)
    })
    .on('data', (data) => {
      list.push(data)
    })
    .on('end', () => {
      ilog.info('client end')
      let res = Buffer.concat(list)
      assert.equal(res.toString(), str)
    })
    .on('finish', () => {
      ilog.info('client finish')
    })

  yield (done) => stream.write(Buffer.from(str), done)
  yield (done) => stream.end(done)
  yield thunk.delay(1000)
  process.exit(0)
})(ilog.error)
