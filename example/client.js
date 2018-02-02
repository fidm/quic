'use strict'

// node example/client.js
const ilog = require('ilog')
const thunk = require('thunks').thunk

const {
  QUICClient
} = require('..')

const cli = new QUICClient()
cli.on('error', ilog.error)

thunk(function * () {
  yield cli.connect(2345)
  yield cli.ping()

  let stream = cli.request()
  stream.on('data', (data) => {
    ilog.info(data.toString())
  })
  yield (done) => stream.write(Buffer.from('hello'), done)
  yield thunk.delay(1000)
})(ilog.error)
