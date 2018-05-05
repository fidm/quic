'use strict'
// **Github:** https://github.com/fidm/quic
//
// **License:** MIT

import { promisify } from 'util'
import { AddressInfo } from 'net'
import { Socket } from 'dgram'
import { EventEmitter } from 'events'
import { ilog } from 'ilog'
import { thunk } from 'thunks'
import { suite, it, Test } from 'tman'
import { equal } from 'assert'
import { createHash } from 'crypto'

import { RandDataStream } from './common'
import { kSocket } from '../src/internal/symbol'
import { Client } from '../src/client'
import { Server } from '../src/server'

const onceEmit = promisify(EventEmitter.prototype.once)

function getListener (ee: EventEmitter, name: string): (...args: any[]) => void {
  const res = ee.listeners(name)
  if (res[0] == null) {
    throw new Error(`no Listener: ${name}`)
  }
  return res[0] as (...args: any[]) => void
}

suite('chaos testing', function () {
  function echoServer () {
    return new Server()
      .on('error', (err) => {
        ilog.error(Object.assign(err, { class: 'server error' }))
      })
      .on('session', (session) => {
        session
          .on('error', (err) => {
            ilog.error(Object.assign(err, { class: 'server session error' }))
          })
          .on('stream', (stream) => {
            stream
              .on('error', (err) => {
                ilog.error(Object.assign(err, { class: 'server stream error' }))
              })
              .on('data', (data) => {
                stream.write(data)
              })
              .on('end', () => {
                stream.end()
              })
          })
      })
  }

  suite('echo rand readable stream', function () {
    for (const i of [1, 2, 3, 4, 5]) {
      // random stream & hash stream --(10MB)--> client --> server --(echo)--> client --> hash stream --> hash should equaled
      const bytes = 1024 * 1024 * 2 * i // 2MB random data to echo
      // async/await will lead to "RangeError: Maximum call stack size exceeded" when compiling
      it(`with bytes ${bytes}`, function * (this: Test) {
        this.timeout(1000 * 20)

        const server = echoServer()
        yield server.listen(0)

        const cli1 = new Client()
        cli1.on('error', (err) => {
          ilog(Object.assign(err, { class: 'client error' }))
        })

        yield cli1.connect(server.address().port)

        const stream1 = cli1.request()
        stream1.on('error', (err) => {
          throw Object.assign(err, { class: 'client stream error' })
        })
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

        const cli2 = yield cli1.spawn(server.address().port)
        const stream2 = cli2.request()
        const stream3 = cli2.request()
        stream2.on('error', (err: Error) => {
          throw Object.assign(err, { class: 'client stream error' })
        })
        stream3.on('error', (err: Error) => {
          throw Object.assign(err, { class: 'client stream error' })
        })
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

        yield Promise.all([
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

        yield Promise.all([cli1.close(), cli2.close()])
        yield server.close()
        yield thunk.promise(thunk.delay(500))
      })
    }
  })

  suite('echo rand readable stream when packets out of order', function () {
    for (const i of [1, 2, 3, 4, 5]) {
      // random stream & hash stream --(10MB)--> client --> server --(echo)--> client --> hash stream --> hash should equaled
      const bytes = 1024 * 1024 * 2 * i // 2MB random data to echo
      it(`with bytes ${bytes}`, function * (this: Test) {
        this.timeout(1000 * 200)

        const server = echoServer()
        yield server.listen(0)
        const see = server[kSocket] as EventEmitter
        const serverListener = getListener(see, 'message')
        see.removeListener('message', serverListener)
        see.addListener('message', function (this: Socket, msg: Buffer, rinfo: AddressInfo) {
          const rand = Math.random()
          if (rand < 0.5) {
            setTimeout(() => serverListener.call(this, msg, rinfo), rand * 10) // out-of-order
          } else {
            serverListener.call(this, msg, rinfo)
          }
        })

        const cli1 = new Client()
        cli1.setKeepAlive(true)
        cli1.on('error', (err) => { ilog(Object.assign(err, { class: 'client error' })) })

        yield cli1.connect(server.address().port)
        const cee = cli1[kSocket] as EventEmitter
        const clientListener = getListener(cee, 'message')
        cee.removeListener('message', clientListener)
        cee.addListener('message', function (this: Socket, msg: Buffer, rinfo: AddressInfo) {
          const rand = Math.random()
          if (rand < 0.5) {
            setTimeout(() => clientListener.call(this, msg, rinfo), rand * 10) // out-of-order
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

        const cli2 = yield cli1.spawn(server.address().port)
        cli2.setKeepAlive(true)
        const stream2 = cli2.request()
        const stream3 = cli2.request()
        stream2.on('error', (err: Error) => {
          throw Object.assign(err, { class: 'client stream error' })
        })
        stream3.on('error', (err: Error) => {
          throw Object.assign(err, { class: 'client stream error' })
        })
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

        yield Promise.all([
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

        yield Promise.all([cli1.close(), cli2.close()])
        yield server.close()
        yield thunk.promise(thunk.delay(500))
      })
    }
  })

  suite('echo rand readable stream when packets loss and out of order', function () {
    for (const i of [1, 2, 3, 4]) {
      // random stream & hash stream --(5MB)--> client --> server --(echo)--> client --> hash stream --> hash should equaled
      const bytes = 1024 * 1024 * 1 * i
      const lossRatio = 0.618 * 0.05 * i
      it(`with loss ratio ${lossRatio * 100}%`, function * (this: Test) {
        this.timeout(1000 * 60 * 2)

        const server = echoServer()
        yield server.listen(0)
        const see = server[kSocket] as EventEmitter
        const serverListener = getListener(see, 'message')
        see.removeListener('message', serverListener)
        see.addListener('message', function (this: Socket, msg: Buffer, rinfo: AddressInfo) {
          const rand = Math.random()
          if (rand < lossRatio) {
            return // packet loss
          }
          if (rand < 0.2) {
            setTimeout(() => serverListener.call(this, msg, rinfo), rand * 10) // out-of-order
          } else {
            serverListener.call(this, msg, rinfo)
          }
        })

        const cli1 = new Client()
        cli1.setKeepAlive(true)
        cli1.on('error', (err) => { ilog(Object.assign(err, { class: 'client error' })) })

        yield cli1.connect(server.address().port)
        const cee = cli1[kSocket] as EventEmitter
        const clientListener = getListener(cee, 'message')
        cee.removeListener('message', clientListener)
        cee.addListener('message', function (this: Socket, msg: Buffer, rinfo: AddressInfo) {
          const rand = Math.random()
          if (rand < lossRatio) {
            return // packet loss
          }
          if (rand < 0.2) {
            setTimeout(() => clientListener.call(this, msg, rinfo), rand * 10) // out-of-order
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

        const cli2 = yield cli1.spawn(server.address().port)
        cli2.setKeepAlive(true)
        const stream2 = cli2.request()
        const stream3 = cli2.request()
        stream2.on('error', (err: Error) => {
          throw Object.assign(err, { class: 'client stream error' })
        })
        stream3.on('error', (err: Error) => {
          throw Object.assign(err, { class: 'client stream error' })
        })
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

        yield Promise.all([
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

        yield Promise.all([cli1.close(), cli2.close()])
        yield server.close()
        yield thunk.promise(thunk.delay(500))
      })
    }
  })
})
