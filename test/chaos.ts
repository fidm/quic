'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

import { promisify } from 'util'
import { EventEmitter } from 'events'
import { ilog } from 'ilog'
import { thunk } from 'thunks'
import { suite, it } from 'tman'
import { ok, equal, deepEqual } from 'assert'
import { createHash } from 'crypto'
import { Client, Server } from '../src'
import { RandDataStream } from './common'
import { RegularPacket } from '../src/internal/packet'
import { BufferVisitor } from '../src/internal/common'
import { kSocket } from '../src/internal/symbol'

const onceEmit = promisify(EventEmitter.prototype.once)

suite('chaos testing', function () {
  function echoServer () {
    return new Server()
      .on('error', (err) => { ilog.error(Object.assign(err, { class: 'server error' })) })
      .on('session', (session) => {
        session
          .on('error', (err) => { ilog.error(Object.assign(err, { class: 'server session error' })) })
          .on('stream', (stream) => {
            stream
              .on('error', (err) => { ilog.error(Object.assign(err, { class: 'server stream error' })) })
              .on('data', (data) => {
                stream.write(data)
              })
              .on('end', () => {
                stream.end()
              })
          })
      })
  }

  for (const i of [1, 2, 3, 4, 5]) {
    // random stream & hash stream --(9MB)--> client --> server --(echo)--> client --> hash stream --> hash should equaled
    const bytes = 1024 * 1024 * 9 * i // 99MB random data to echo
    it(`echo rand readable stream with bytes ${bytes}`, async function () {
      this.timeout(1000 * 100)

      const server = echoServer()
      await server.listen(0)

      const cli1 = new Client()
      cli1.on('error', (err) => { ilog(Object.assign(err, { class: 'client error' })) })

      await cli1.connect(server.address().port)

      const stream1 = cli1.request()
      stream1.on('error', (err) => { throw Object.assign(err, { class: 'client stream error' })})
      const dataStream1 = new RandDataStream(bytes)
      stream1.on('drain', () => {
        dataStream1.resume()
      })
      // randDataStream.pipe(stream) // use paused mode for large stream
      dataStream1
        .on('data', (chunk) => {
          if (!stream1.write(chunk)) {
            dataStream1.pause()
          }
        })
        .on('end', () => stream1.end())

      const hash1 = createHash('sha256')
      stream1.pipe(hash1)

      const cli2 = await cli1.spawn(server.address().port)
      const stream2 = cli2.request()
      const stream3 = cli2.request()
      stream2.on('error', (err) => { throw Object.assign(err, { class: 'client stream error' })})
      stream3.on('error', (err) => { throw Object.assign(err, { class: 'client stream error' })})
      const dataStream2 = new RandDataStream(bytes)
      stream3.on('drain', () => {
        dataStream2.resume()
      })
      dataStream2
        .on('data', (chunk) => {
          stream2.write(chunk)
          if (!stream3.write(chunk)) {
            dataStream2.pause()
          }
        })
        .on('end', () => {
          stream2.end()
          stream3.end()
        })

      const hash2 = createHash('sha256')
      stream2.pipe(hash2)
      const hash3 = createHash('sha256')
      stream3.pipe(hash3)

      await Promise.all([
        onceEmit.call(stream1, 'end'),
        onceEmit.call(stream2, 'end'),
        onceEmit.call(stream3, 'end'),
      ])

      equal(dataStream1.readBytes, bytes)
      equal(dataStream1.totalSize, bytes)
      equal(stream1.bytesRead, bytes)
      equal(stream1.bytesWritten, bytes)
      const ret1 = hash1.read() as Buffer
      equal(ret1.toString('hex'), dataStream1.sum)

      equal(dataStream2.readBytes, bytes)
      equal(dataStream2.totalSize, bytes)
      equal(stream2.bytesRead, bytes)
      equal(stream2.bytesWritten, bytes)
      const ret2 = hash2.read() as Buffer
      equal(ret2.toString('hex'), dataStream2.sum)

      equal(stream3.bytesRead, bytes)
      equal(stream3.bytesWritten, bytes)
      const ret3 = hash3.read() as Buffer
      equal(ret3.toString('hex'), dataStream2.sum)

      await Promise.all([cli1.close(), cli2.close()])
      await server.close()
      await thunk.promise(thunk.delay(500))
    })
  }

  for (const i of [5, 4, 3, 2, 1, 0]) {
    // random stream & hash stream --(9MB)--> client --> server --(echo)--> client --> hash stream --> hash should equaled
    const bytes = 1024 * 1024 * 9 * i
    const lossRatio = 0.618 - 0.1 * i
    it(`echo rand readable stream with packets loss ${lossRatio * 100}%`, async function () {
      this.timeout(1000 * 600)

      const server = echoServer()
      await server.listen(0)
      const serverListener = server[kSocket].listeners('message')[0]
      server[kSocket].removeListener('message', serverListener)
      server[kSocket].addListener('message', function (msg: Buffer, rinfo: AddressInfo) {
        if (Math.random() < lossRatio) {
          return // packet loss
        }
        if (Math.random() < 0.5) {
          setTimeout(() => serverListener.call(this, msg, rinfo)) // out-of-order
        } else {
          serverListener.call(this, msg, rinfo)
        }
      })

      const cli1 = new Client()
      cli1.setKeepAlive(true)
      cli1.on('error', (err) => { ilog(Object.assign(err, { class: 'client error' })) })

      await cli1.connect(server.address().port)
      const clientListener = cli1[kSocket].listeners('message')[0]
      cli1[kSocket].removeListener('message', clientListener)
      cli1[kSocket].addListener('message', function (msg: Buffer, rinfo: AddressInfo) {
        if (Math.random() < lossRatio) {
          return // packet loss
        }
        if (Math.random() < 0.5) {
          setTimeout(() => clientListener.call(this, msg, rinfo)) // out-of-order
        } else {
          clientListener.call(this, msg, rinfo)
        }
      })

      const stream1 = cli1.request()
      stream1.on('error', (err) => { throw Object.assign(err, { class: 'client stream error' })})
      const dataStream1 = new RandDataStream(bytes)
      stream1.on('drain', () => {
        dataStream1.resume()
      })
      // randDataStream.pipe(stream) // use paused mode for large stream
      dataStream1
        .on('data', (chunk) => {
          if (!stream1.write(chunk)) {
            dataStream1.pause()
          }
        })
        .on('end', () => stream1.end())

      const hash1 = createHash('sha256')
      stream1.pipe(hash1)

      const cli2 = await cli1.spawn(server.address().port)
      cli2.setKeepAlive(true)
      const stream2 = cli2.request()
      const stream3 = cli2.request()
      stream2.on('error', (err) => { throw Object.assign(err, { class: 'client stream error' })})
      stream3.on('error', (err) => { throw Object.assign(err, { class: 'client stream error' })})
      const dataStream2 = new RandDataStream(bytes)
      stream3.on('drain', () => {
        dataStream2.resume()
      })
      dataStream2
        .on('data', (chunk) => {
          stream2.write(chunk)
          if (!stream3.write(chunk)) {
            dataStream2.pause()
          }
        })
        .on('end', () => {
          stream2.end()
          stream3.end()
        })

      const hash2 = createHash('sha256')
      stream2.pipe(hash2)
      const hash3 = createHash('sha256')
      stream3.pipe(hash3)

      await Promise.all([
        onceEmit.call(stream1, 'end'),
        onceEmit.call(stream2, 'end'),
        onceEmit.call(stream3, 'end'),
      ])

      equal(dataStream1.readBytes, bytes)
      equal(dataStream1.totalSize, bytes)
      equal(stream1.bytesRead, bytes)
      equal(stream1.bytesWritten, bytes)
      const ret1 = hash1.read() as Buffer
      equal(ret1.toString('hex'), dataStream1.sum)

      equal(dataStream2.readBytes, bytes)
      equal(dataStream2.totalSize, bytes)
      equal(stream2.bytesRead, bytes)
      equal(stream2.bytesWritten, bytes)
      const ret2 = hash2.read() as Buffer
      equal(ret2.toString('hex'), dataStream2.sum)

      equal(stream3.bytesRead, bytes)
      equal(stream3.bytesWritten, bytes)
      const ret3 = hash3.read() as Buffer
      equal(ret3.toString('hex'), dataStream2.sum)

      await Promise.all([cli1.close(), cli2.close()])
      await server.close()
      await thunk.promise(thunk.delay(500))
    })
  }
})
