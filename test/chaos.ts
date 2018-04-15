'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

import * as ilog from 'ilog'
import { thunk } from 'thunks'
import { suite, it } from 'tman'
import { ok, equal, deepEqual } from 'assert'
import { createHash } from 'crypto'
import { Client, Server } from '../src'
import { RandDataStream } from './common'

suite('chaos testing', function () {
  this.timeout(1200 * 1000)

  function echoServer () {
    return new Server()
      .on('error', (err) => { ilog(Object.assign(err, { class: 'server error' })) })
      .on('session', (session) => {
        session
          .on('error', (err) => { ilog(Object.assign(err, { class: 'server session error' })) })
          .on('stream', (stream) => {
            stream
              .on('error', (err) => { ilog(Object.assign(err, { class: 'server stream error' })) })
              .on('data', (data) => {
                if (stream.bytesRead % 1024 === 0) {
                  process.stdout.write('.')
                }
                stream.write(data)
              })
              .on('end', () => stream.end())
          })
      })
  }

  it('echo rand readable stream', function * () {
    const bytes = 1024 * 1024 * 99 // 99MB random data to echo
    const server = echoServer()
    yield server.listen(0)

    const cli = new Client()
    cli.on('error', (err) => { ilog(Object.assign(err, { class: 'client error' })) })

    yield cli.connect(server.address().port)
    yield cli.ping()

    const stream = cli.request()
    stream.on('error', (err) => { throw Object.assign(err, { class: 'client stream error' })})
    const randDataStream = new RandDataStream(bytes)
    // randDataStream.pipe(stream)
    // use paused mode for large stream
    randDataStream
      .on('data', (chunk) => {
        if (!stream.write(chunk)) {
          randDataStream.pause()
        }
      })
      .on('end', () => stream.end())

    stream.on('drain', () => {
      randDataStream.resume()
    })

    const hash = createHash('sha256')
    stream.pipe(hash)

    yield (done) => stream.once('end', done)
    equal(randDataStream.readBytes, bytes)
    equal(randDataStream.totalSize, bytes)
    equal(stream.bytesRead, bytes)
    equal(stream.bytesWritten, bytes)

    const data = hash.read() as Buffer
    equal(data.toString('hex'), randDataStream.sum)

    yield cli.close()
    yield server.close()
    yield thunk.delay(500)
  })
})
