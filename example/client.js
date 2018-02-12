'use strict'

// node example/client.js

const assert = require('assert')
const ilog = require('ilog')
const thunk = require('thunks').thunk

const {
  Client
} = require('../dist/index')

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
  let res = ''
  stream
    .on('data', (data) => {
      res += data.toString()
    })
    .on('end', () => {
      ilog.info('client end')
      assert.equal(res, str)
    })
    .on('finish', () => {
      ilog.info('client finish')
    })

  yield (done) => stream.write(Buffer.from(str), done)
  yield (done) => stream.end(done)
  yield thunk.delay(1000)
})(ilog.error)
