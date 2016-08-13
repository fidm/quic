'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const tman = require('tman')
const assert = require('assert')
const QuicId = require('../lib/id')
const bufferFromBytes = require('./util').bufferFromBytes

tman.suite('QuicId', function () {
  tman.suite('ConnectionID', function () {
    const ConnectionID = QuicId.ConnectionID

    tman.it('ConnectionID.random, ConnectionID.fromString', function () {
      let connectionID = ConnectionID.random()
      assert.strictEqual(connectionID.toBuffer().length, 8)
      assert.strictEqual(connectionID.toString().length, 16)
      assert.ok(connectionID.equals(ConnectionID.fromString(connectionID.toString())))
    })
  })

  tman.suite('PacketNumber', function () {
    const PacketNumber = QuicId.PacketNumber

    tman.it('new PacketNumber', function () {
      let packetNumber = new PacketNumber(bufferFromBytes([0x1]))
      assert.strictEqual(packetNumber.id, 1)
      assert.ok(packetNumber.toBuffer().equals(bufferFromBytes([0x1])))

      packetNumber = new PacketNumber(bufferFromBytes([0x0, 0x1, 0x0, 0x0]))
      assert.strictEqual(packetNumber.id, 0x100)
      assert.ok(packetNumber.toBuffer().equals(bufferFromBytes([0x0, 0x1])))

      packetNumber = new PacketNumber(bufferFromBytes([0x0, 0x0, 0x1, 0x0, 0x0, 0x0]))
      assert.strictEqual(packetNumber.id, 0x10000)
      assert.ok(packetNumber.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x1, 0x0])))

      packetNumber = new PacketNumber(bufferFromBytes([
        0x0, 0x0, 0x0, 0x0,
        0x1, 0x0, 0x0, 0x0
      ]))
      assert.strictEqual(packetNumber.id, 0x100000000)
      assert.ok(packetNumber.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x1, 0x0])))

      assert.throws(() => new PacketNumber(bufferFromBytes([
        0x0, 0x0, 0x0, 0x0,
        0x1, 0x0, 0x1, 0x0
      ])))
    })

    tman.it('PacketNumber.fromId', function () {
      let id = 1  // 8 bits
      let packetNumber = PacketNumber.fromId(id)
      assert.strictEqual(packetNumber.id, id)
      assert.ok(packetNumber.toBuffer().equals(bufferFromBytes([0x1])))

      id = 0x100  // 16 bits
      packetNumber = PacketNumber.fromId(id)
      assert.strictEqual(packetNumber.id, id)
      assert.ok(packetNumber.toBuffer().equals(bufferFromBytes([0x0, 0x1])))

      id = 0x10000 // 32 bits
      packetNumber = PacketNumber.fromId(id)
      assert.strictEqual(packetNumber.id, id)
      assert.ok(packetNumber.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x1, 0x0])))

      id = 0x100000000 // 48 bits
      packetNumber = PacketNumber.fromId(id)
      assert.strictEqual(packetNumber.id, id)
      assert.ok(packetNumber.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x1, 0x0])))

      id = 0x1000000000000 // > 48 bit
      assert.throws(() => PacketNumber.fromId(id))
    })

    tman.it('packetNumber.equals', function () {
      assert.ok(PacketNumber.fromId(1).equals(new PacketNumber(bufferFromBytes([0x1]))))
      assert.ok(PacketNumber.fromId(0x10000)
        .equals(new PacketNumber(bufferFromBytes([0x0, 0x0, 0x1, 0x0, 0x0, 0x0]))))
      assert.ok(!PacketNumber.fromId(0x10000)
        .equals(new PacketNumber(bufferFromBytes([0x0, 0x0, 0x0, 0x1, 0x0, 0x0]))))
    })

    tman.it('packetNumber.toFullBuffer', function () {
      assert.ok(bufferFromBytes([0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]).equals(
        new PacketNumber(bufferFromBytes([0x1])).toFullBuffer()))
      assert.ok(bufferFromBytes([0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0]).equals(
        new PacketNumber(bufferFromBytes([0x0, 0x0, 0x0, 0x1])).toFullBuffer()))
    })

    tman.it('packetNumber.nextNumber', function () {
      let packetNumber = PacketNumber.fromId(1)
      packetNumber = packetNumber.nextNumber()
      assert.strictEqual(packetNumber.id, 2)
      assert.strictEqual(packetNumber.nextNumber().id, 3)
      assert.strictEqual(PacketNumber.fromId(0xffffffffffff).nextNumber().id, 1)
    })
  })

  tman.suite('SocketAddress', function () {
    const SocketAddress = QuicId.SocketAddress

    tman.it('SocketAddress, IPv4', function () {
      let socketAddress = SocketAddress.fromObject(
        {port: 3000, family: 'IPv4', address: '127.0.0.1'})
      let res = new SocketAddress(socketAddress.toBuffer())
      assert.deepEqual(socketAddress, res)

      socketAddress = SocketAddress.fromObject(
        {port: 0x1234, family: 'IPv4', address: '4.31.198.44'})
      assert.ok(socketAddress.toBuffer().equals(bufferFromBytes([
        0x02, 0x00, 0x04, 0x1f, 0xc6, 0x2c, 0x34, 0x12
      ])))
    })

    tman.it('SocketAddress, IPv6', function () {
      let socketAddress = SocketAddress.fromObject(
        {port: 65534, family: 'IPv6', address: '::1'})
      assert.strictEqual(socketAddress.address, '0:0:0:0:0:0:0:1')
      let res = new SocketAddress(socketAddress.toBuffer())
      assert.deepEqual(socketAddress, res)

      socketAddress = SocketAddress.fromObject({
        port: 0x5678, family: 'IPv6', address: '2001:700:300:1800::'})
      assert.strictEqual(socketAddress.address, '2001:700:300:1800:0:0:0:0')
      res = new SocketAddress(socketAddress.toBuffer())
      assert.deepEqual(socketAddress, res)

      socketAddress = SocketAddress.fromObject({
        port: 0x5678, family: 'IPv6', address: '2001:700:300:1800::f'})
      assert.ok(socketAddress.toBuffer().equals(bufferFromBytes([
        0x0a, 0x00,
        0x20, 0x01, 0x07, 0x00, 0x03, 0x00, 0x18, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
        0x78, 0x56
      ])))
    })
  })
})
