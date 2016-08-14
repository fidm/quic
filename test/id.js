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
      assert.throws(() => new PacketNumber(bufferFromBytes([])))
      let packetNumber = new PacketNumber(bufferFromBytes([0x0]))
      assert.strictEqual(packetNumber.value, 0)
      assert.ok(packetNumber.toBuffer().equals(bufferFromBytes([0x0])))

      packetNumber = new PacketNumber(bufferFromBytes([0x1]))
      assert.strictEqual(packetNumber.value, 1)
      assert.ok(packetNumber.toBuffer().equals(bufferFromBytes([0x1])))

      packetNumber = new PacketNumber(bufferFromBytes([0x0, 0x1, 0x0, 0x0]))
      assert.strictEqual(packetNumber.value, 0x100)
      assert.ok(packetNumber.toBuffer().equals(bufferFromBytes([0x0, 0x1])))

      packetNumber = new PacketNumber(bufferFromBytes([0x0, 0x0, 0x1]))
      assert.strictEqual(packetNumber.value, 0x10000)
      assert.ok(packetNumber.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x1, 0x0])))

      packetNumber = new PacketNumber(bufferFromBytes([0x0, 0x0, 0x1, 0x0, 0x0, 0x0]))
      assert.strictEqual(packetNumber.value, 0x10000)
      assert.ok(packetNumber.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x1, 0x0])))

      packetNumber = new PacketNumber(bufferFromBytes([
        0x0, 0x0, 0x0, 0x0,
        0x1, 0x0, 0x0, 0x0
      ]))
      assert.strictEqual(packetNumber.value, 0x100000000)
      assert.ok(packetNumber.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x1, 0x0])))

      assert.throws(() => new PacketNumber(bufferFromBytes([
        0x0, 0x0, 0x0, 0x0,
        0x1, 0x0, 0x1, 0x0
      ])))
    })

    tman.it('PacketNumber.fromValue', function () {
      let id = 0  // 8 bits
      let packetNumber = PacketNumber.fromValue(id)
      assert.strictEqual(packetNumber.value, id)
      assert.ok(packetNumber.toBuffer().equals(bufferFromBytes([0x0])))

      id = 1  // 8 bits
      packetNumber = PacketNumber.fromValue(id)
      assert.strictEqual(packetNumber.value, id)
      assert.ok(packetNumber.toBuffer().equals(bufferFromBytes([0x1])))

      id = 0x100  // 16 bits
      packetNumber = PacketNumber.fromValue(id)
      assert.strictEqual(packetNumber.value, id)
      assert.ok(packetNumber.toBuffer().equals(bufferFromBytes([0x0, 0x1])))

      id = 0x10000 // 32 bits
      packetNumber = PacketNumber.fromValue(id)
      assert.strictEqual(packetNumber.value, id)
      assert.ok(packetNumber.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x1, 0x0])))

      id = 0x100000000 // 48 bits
      packetNumber = PacketNumber.fromValue(id)
      assert.strictEqual(packetNumber.value, id)
      assert.ok(packetNumber.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x1, 0x0])))

      id = 0x1000000000000 // > 48 bit
      assert.throws(() => PacketNumber.fromValue(id))
    })

    tman.it('packetNumber.equals', function () {
      assert.ok(PacketNumber.fromValue(1).equals(new PacketNumber(bufferFromBytes([0x1]))))
      assert.ok(PacketNumber.fromValue(0x10000)
        .equals(new PacketNumber(bufferFromBytes([0x0, 0x0, 0x1, 0x0, 0x0, 0x0]))))
      assert.ok(!PacketNumber.fromValue(0x10000)
        .equals(new PacketNumber(bufferFromBytes([0x0, 0x0, 0x0, 0x1, 0x0, 0x0]))))
    })

    tman.it('packetNumber.toFullBuffer', function () {
      assert.ok(bufferFromBytes([0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]).equals(
        new PacketNumber(bufferFromBytes([0x1])).toFullBuffer()))
      assert.ok(bufferFromBytes([0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0]).equals(
        new PacketNumber(bufferFromBytes([0x0, 0x0, 0x0, 0x1])).toFullBuffer()))
    })

    tman.it('packetNumber.nextNumber', function () {
      let packetNumber = PacketNumber.fromValue(1)
      packetNumber = packetNumber.nextNumber()
      assert.strictEqual(packetNumber.value, 2)
      assert.strictEqual(packetNumber.nextNumber().value, 3)
      assert.strictEqual(PacketNumber.fromValue(0xffffffffffff).nextNumber().value, 1)
    })

    tman.it('packetNumber.flagBits', function () {
      let packetNumber = new PacketNumber(bufferFromBytes([0x1]))
      assert.strictEqual(packetNumber.flagBits, 0b00)

      packetNumber = new PacketNumber(bufferFromBytes([0x1, 0x1]))
      assert.strictEqual(packetNumber.flagBits, 0b01)

      packetNumber = new PacketNumber(bufferFromBytes([0x1, 0x1, 0x1]))
      assert.strictEqual(packetNumber.flagBits, 0b10)
      packetNumber = new PacketNumber(bufferFromBytes([0x1, 0x1, 0x1, 0x1]))
      assert.strictEqual(packetNumber.flagBits, 0b10)

      packetNumber = new PacketNumber(bufferFromBytes([0x1, 0x1, 0x1, 0x1, 0x1]))
      assert.strictEqual(packetNumber.flagBits, 0b11)
      packetNumber = new PacketNumber(bufferFromBytes([0x1, 0x1, 0x1, 0x1, 0x1, 0x1]))
      assert.strictEqual(packetNumber.flagBits, 0b11)
    })

    tman.it('PacketNumber.flagToByteLen', function () {
      assert.strictEqual(PacketNumber.flagToByteLen(0b00), 1)
      assert.strictEqual(PacketNumber.flagToByteLen(0b01), 2)
      assert.strictEqual(PacketNumber.flagToByteLen(0b10), 4)
      assert.strictEqual(PacketNumber.flagToByteLen(0b11), 6)
    })
  })

  tman.suite('StreamID', function () {
    const StreamID = QuicId.StreamID

    tman.it('new StreamID', function () {
      assert.throws(() => new StreamID(bufferFromBytes([])))

      let streamID = new StreamID(bufferFromBytes([0x0]))
      assert.strictEqual(streamID.value, 0)
      assert.ok(streamID.toBuffer().equals(bufferFromBytes([0x0])))

      streamID = new StreamID(bufferFromBytes([0x1]))
      assert.strictEqual(streamID.value, 1)
      assert.ok(streamID.toBuffer().equals(bufferFromBytes([0x1])))

      streamID = new StreamID(bufferFromBytes([0x0, 0x1, 0x0, 0x0]))
      assert.strictEqual(streamID.value, 0x100)
      assert.ok(streamID.toBuffer().equals(bufferFromBytes([0x0, 0x1])))

      streamID = new StreamID(bufferFromBytes([0x0, 0x0, 0x1, 0x0]))
      assert.strictEqual(streamID.value, 0x10000)
      assert.ok(streamID.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x1])))

      streamID = new StreamID(bufferFromBytes([0x0, 0x0, 0x1, 0x0, 0x0, 0x0]))
      assert.strictEqual(streamID.value, 0x10000)
      assert.ok(streamID.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x1])))

      streamID = new StreamID(bufferFromBytes([
        0x0, 0x0, 0x0, 0x1,
        0x0, 0x0, 0x0, 0x0
      ]))
      assert.strictEqual(streamID.value, 0x1000000)
      assert.ok(streamID.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x0, 0x1])))

      assert.throws(() => new StreamID(bufferFromBytes([
        0x0, 0x0, 0x0, 0x0,
        0x1, 0x0, 0x0, 0x0
      ])))
    })

    tman.it('StreamID.fromValue', function () {
      let id = 0  // 8 bits
      let streamID = StreamID.fromValue(id)
      assert.strictEqual(streamID.value, id)
      assert.ok(streamID.toBuffer().equals(bufferFromBytes([0x0])))

      id = 1  // 8 bits
      streamID = StreamID.fromValue(id)
      assert.strictEqual(streamID.value, id)
      assert.ok(streamID.toBuffer().equals(bufferFromBytes([0x1])))

      id = 0x100  // 16 bits
      streamID = StreamID.fromValue(id)
      assert.strictEqual(streamID.value, id)
      assert.ok(streamID.toBuffer().equals(bufferFromBytes([0x0, 0x1])))

      id = 0x10000 // 24 bits
      streamID = StreamID.fromValue(id)
      assert.strictEqual(streamID.value, id)
      assert.ok(streamID.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x1])))

      id = 0x1000000 // 32 bits
      streamID = StreamID.fromValue(id)
      assert.strictEqual(streamID.value, id)
      assert.ok(streamID.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x0, 0x1])))

      id = 0x100000000 // > 32 bit
      assert.throws(() => StreamID.fromValue(id))
    })

    tman.it('StreamID.equals', function () {
      assert.ok(StreamID.fromValue(1).equals(new StreamID(bufferFromBytes([0x1]))))
      assert.ok(StreamID.fromValue(0x10000)
        .equals(new StreamID(bufferFromBytes([0x0, 0x0, 0x1, 0x0, 0x0, 0x0]))))
      assert.ok(!StreamID.fromValue(0x10000)
        .equals(new StreamID(bufferFromBytes([0x0, 0x0, 0x0, 0x1, 0x0, 0x0]))))
    })

    tman.it('StreamID.toFullBuffer', function () {
      assert.ok(bufferFromBytes([0x1, 0x0, 0x0, 0x0]).equals(
        new StreamID(bufferFromBytes([0x1])).toFullBuffer()))
      assert.ok(bufferFromBytes([0x0, 0x0, 0x0, 0x1]).equals(
        new StreamID(bufferFromBytes([0x0, 0x0, 0x0, 0x1])).toFullBuffer()))
    })

    tman.it('StreamID.nextID', function () {
      let streamID1 = StreamID.fromValue(1)
      let streamID2 = StreamID.fromValue(2)
      streamID1 = streamID1.nextID()
      assert.strictEqual(streamID1.value, 3)
      assert.strictEqual(streamID1.nextID().value, 5)
      assert.strictEqual(streamID2.nextID().value, 4)
      assert.strictEqual(StreamID.fromValue(0xffffffff).nextID().value, 2)
      assert.strictEqual(StreamID.fromValue(0xffffffff - 1).nextID().value, 1)
    })

    tman.it('streamID.flagBits', function () {
      let streamID = new StreamID(bufferFromBytes([0x1]))
      assert.strictEqual(streamID.flagBits, 0b00)

      streamID = new StreamID(bufferFromBytes([0x1, 0x1]))
      assert.strictEqual(streamID.flagBits, 0b01)

      streamID = new StreamID(bufferFromBytes([0x1, 0x1, 0x1]))
      assert.strictEqual(streamID.flagBits, 0b10)

      streamID = new StreamID(bufferFromBytes([0x1, 0x1, 0x1, 0x1]))
      assert.strictEqual(streamID.flagBits, 0b11)
    })

    tman.it('StreamID.flagToByteLen', function () {
      assert.strictEqual(StreamID.flagToByteLen(0b00), 1)
      assert.strictEqual(StreamID.flagToByteLen(0b01), 2)
      assert.strictEqual(StreamID.flagToByteLen(0b10), 3)
      assert.strictEqual(StreamID.flagToByteLen(0b11), 4)
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

  tman.suite('Offset', function () {
    const Offset = QuicId.Offset

    tman.it('new Offset', function () {
      let offset = new Offset(bufferFromBytes([]))
      assert.strictEqual(offset.value, 0)
      assert.ok(offset.toBuffer().equals(bufferFromBytes([])))

      offset = new Offset(bufferFromBytes([0x1]))
      assert.strictEqual(offset.value, 1)
      assert.ok(offset.toBuffer().equals(bufferFromBytes([0x1, 0x0])))

      offset = new Offset(bufferFromBytes([0x0, 0x1, 0x0, 0x0]))
      assert.strictEqual(offset.value, 0x100)
      assert.ok(offset.toBuffer().equals(bufferFromBytes([0x0, 0x1])))

      offset = new Offset(bufferFromBytes([0x0, 0x0, 0x1, 0x0, 0x0, 0x0]))
      assert.strictEqual(offset.value, 0x10000)
      assert.ok(offset.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x1])))

      offset = new Offset(bufferFromBytes([
        0x0, 0x0, 0x0, 0x0,
        0x1, 0x0, 0x0, 0x0
      ]))
      assert.strictEqual(offset.value, 0x100000000)
      assert.ok(offset.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x1])))

      offset = new Offset(bufferFromBytes([
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x1, 0x0, 0x0
      ]))
      assert.strictEqual(offset.value, 0x010000000000)
      assert.ok(offset.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x0, 0x1])))

      assert.throws(() => new Offset(bufferFromBytes([
        0x0, 0x0, 0x0, 0x0,
        0x1, 0x0, 0x1, 0x0
      ])))
    })

    tman.it('Offset.fromValue', function () {
      let value = 0  // 0 bits
      let offset = Offset.fromValue(value)
      assert.strictEqual(offset.value, 0)
      assert.ok(offset.toBuffer().equals(bufferFromBytes([])))

      value = 1  // 16 bits
      offset = Offset.fromValue(value)
      assert.strictEqual(offset.value, value)
      assert.ok(offset.toBuffer().equals(bufferFromBytes([0x1, 0x0])))

      value = 0x0100  // 16 bits
      offset = Offset.fromValue(value)
      assert.strictEqual(offset.value, value)
      assert.ok(offset.toBuffer().equals(bufferFromBytes([0x0, 0x1])))

      value = 0x010000 // 24 bits
      offset = Offset.fromValue(value)
      assert.strictEqual(offset.value, value)
      assert.ok(offset.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x1])))

      value = 0x01000000 // 32 bits
      offset = Offset.fromValue(value)
      assert.strictEqual(offset.value, value)
      assert.ok(offset.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x0, 0x1])))

      value = 0x0100000000 // 40 bits
      offset = Offset.fromValue(value)
      assert.strictEqual(offset.value, value)
      assert.ok(offset.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x1])))

      value = 0x010000000000 // 48 bits
      offset = Offset.fromValue(value)
      assert.strictEqual(offset.value, value)
      assert.ok(offset.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x0, 0x1])))

      value = 0x1000000000000 // > 48 bit
      assert.throws(() => Offset.fromValue(value))
    })

    tman.it('offset.toFullBuffer', function () {
      assert.ok(bufferFromBytes([0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]).equals(
        new Offset(bufferFromBytes([0x1])).toFullBuffer()))
      assert.ok(bufferFromBytes([0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0]).equals(
        new Offset(bufferFromBytes([0x0, 0x0, 0x0, 0x1])).toFullBuffer()))
    })

    tman.it('offset.nextOffset', function () {
      let offset = Offset.fromValue(64)
      assert.strictEqual(offset.value, 64)
      offset = offset.nextOffset(64)
      assert.strictEqual(offset.value, 128)
      offset = offset.nextOffset(32)
      assert.strictEqual(offset.value, 160)
    })

    tman.it('offset.flagBits', function () {
      let offset = new Offset(bufferFromBytes([]))
      assert.strictEqual(offset.flagBits, 0b000)

      offset = new Offset(bufferFromBytes([0x1]))
      assert.strictEqual(offset.flagBits, 0b001)

      offset = new Offset(bufferFromBytes([0x1, 0x1]))
      assert.strictEqual(offset.flagBits, 0b001)

      offset = new Offset(bufferFromBytes([0x1, 0x1, 0x1]))
      assert.strictEqual(offset.flagBits, 0b010)

      offset = new Offset(bufferFromBytes([0x1, 0x1, 0x1, 0x1]))
      assert.strictEqual(offset.flagBits, 0b011)

      offset = new Offset(bufferFromBytes([0x1, 0x1, 0x1, 0x1, 0x1]))
      assert.strictEqual(offset.flagBits, 0b100)

      offset = new Offset(bufferFromBytes([0x1, 0x1, 0x1, 0x1, 0x1, 0x1]))
      assert.strictEqual(offset.flagBits, 0b101)
    })

    tman.it('Offset.flagToByteLen', function () {
      assert.strictEqual(Offset.flagToByteLen(0b000), 0)
      assert.strictEqual(Offset.flagToByteLen(0b001), 2)
      assert.strictEqual(Offset.flagToByteLen(0b010), 3)
      assert.strictEqual(Offset.flagToByteLen(0b011), 4)
      assert.strictEqual(Offset.flagToByteLen(0b100), 5)
      assert.strictEqual(Offset.flagToByteLen(0b101), 6)
      assert.strictEqual(Offset.flagToByteLen(0b110), 7)
      assert.strictEqual(Offset.flagToByteLen(0b111), 8)
    })
  })
})
