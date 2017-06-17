'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const { suite, it } = require('tman')
const { ok, strictEqual, deepEqual, throws } = require('assert')

const { ConnectionID, PacketNumber, StreamID, SocketAddress, Offset } = require('../lib/protocol')
const { bufferFromBytes } = require('./common')

suite('QUIC Protocol', function () {
  suite('ConnectionID', function () {
    it('ConnectionID.random, ConnectionID.fromString', function () {
      let connectionID = ConnectionID.random()
      strictEqual(connectionID.toBuffer().length, 8)
      strictEqual(connectionID.toString().length, 16)
      ok(connectionID.equals(ConnectionID.fromString(connectionID.toString())))
    })
  })

  suite('PacketNumber', function () {
    it('new PacketNumber', function () {
      throws(() => new PacketNumber(bufferFromBytes([])))
      let packetNumber = new PacketNumber(bufferFromBytes([0x0]))
      strictEqual(packetNumber.value, 0)
      ok(packetNumber.toBuffer().equals(bufferFromBytes([0x0])))

      packetNumber = new PacketNumber(bufferFromBytes([0x1]))
      strictEqual(packetNumber.value, 1)
      ok(packetNumber.toBuffer().equals(bufferFromBytes([0x1])))

      packetNumber = new PacketNumber(bufferFromBytes([0x0, 0x1, 0x0, 0x0]))
      strictEqual(packetNumber.value, 0x100)
      ok(packetNumber.toBuffer().equals(bufferFromBytes([0x0, 0x1])))

      packetNumber = new PacketNumber(bufferFromBytes([0x0, 0x0, 0x1]))
      strictEqual(packetNumber.value, 0x10000)
      ok(packetNumber.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x1, 0x0])))

      packetNumber = new PacketNumber(bufferFromBytes([0x0, 0x0, 0x1, 0x0, 0x0, 0x0]))
      strictEqual(packetNumber.value, 0x10000)
      ok(packetNumber.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x1, 0x0])))

      packetNumber = new PacketNumber(bufferFromBytes([
        0x0, 0x0, 0x0, 0x0,
        0x1, 0x0, 0x0, 0x0
      ]))
      strictEqual(packetNumber.value, 0x100000000)
      ok(packetNumber.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x1, 0x0])))

      throws(() => new PacketNumber(bufferFromBytes([
        0x0, 0x0, 0x0, 0x0,
        0x1, 0x0, 0x1, 0x0
      ])))
    })

    it('PacketNumber.fromValue', function () {
      let id = 0  // 8 bits
      let packetNumber = PacketNumber.fromValue(id)
      strictEqual(packetNumber.value, id)
      ok(packetNumber.toBuffer().equals(bufferFromBytes([0x0])))

      id = 1  // 8 bits
      packetNumber = PacketNumber.fromValue(id)
      strictEqual(packetNumber.value, id)
      ok(packetNumber.toBuffer().equals(bufferFromBytes([0x1])))

      id = 0x100  // 16 bits
      packetNumber = PacketNumber.fromValue(id)
      strictEqual(packetNumber.value, id)
      ok(packetNumber.toBuffer().equals(bufferFromBytes([0x0, 0x1])))

      id = 0x10000 // 32 bits
      packetNumber = PacketNumber.fromValue(id)
      strictEqual(packetNumber.value, id)
      ok(packetNumber.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x1, 0x0])))

      id = 0x100000000 // 48 bits
      packetNumber = PacketNumber.fromValue(id)
      strictEqual(packetNumber.value, id)
      ok(packetNumber.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x1, 0x0])))

      id = 0x1000000000000 // > 48 bit
      throws(() => PacketNumber.fromValue(id))
    })

    it('packetNumber.equals', function () {
      ok(PacketNumber.fromValue(1).equals(new PacketNumber(bufferFromBytes([0x1]))))
      ok(PacketNumber.fromValue(0x10000)
        .equals(new PacketNumber(bufferFromBytes([0x0, 0x0, 0x1, 0x0, 0x0, 0x0]))))
      ok(!PacketNumber.fromValue(0x10000)
        .equals(new PacketNumber(bufferFromBytes([0x0, 0x0, 0x0, 0x1, 0x0, 0x0]))))
    })

    it('packetNumber.toFullBuffer', function () {
      ok(bufferFromBytes([0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]).equals(
        new PacketNumber(bufferFromBytes([0x1])).toFullBuffer()))
      ok(bufferFromBytes([0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0]).equals(
        new PacketNumber(bufferFromBytes([0x0, 0x0, 0x0, 0x1])).toFullBuffer()))
    })

    it('packetNumber.nextNumber', function () {
      let packetNumber = PacketNumber.fromValue(1)
      packetNumber = packetNumber.nextNumber()
      strictEqual(packetNumber.value, 2)
      strictEqual(packetNumber.nextNumber().value, 3)
      strictEqual(PacketNumber.fromValue(0xffffffffffff).nextNumber().value, 1)
    })

    it('packetNumber.flagBits', function () {
      let packetNumber = new PacketNumber(bufferFromBytes([0x1]))
      strictEqual(packetNumber.flagBits, 0b00)

      packetNumber = new PacketNumber(bufferFromBytes([0x1, 0x1]))
      strictEqual(packetNumber.flagBits, 0b01)

      packetNumber = new PacketNumber(bufferFromBytes([0x1, 0x1, 0x1]))
      strictEqual(packetNumber.flagBits, 0b10)
      packetNumber = new PacketNumber(bufferFromBytes([0x1, 0x1, 0x1, 0x1]))
      strictEqual(packetNumber.flagBits, 0b10)

      packetNumber = new PacketNumber(bufferFromBytes([0x1, 0x1, 0x1, 0x1, 0x1]))
      strictEqual(packetNumber.flagBits, 0b11)
      packetNumber = new PacketNumber(bufferFromBytes([0x1, 0x1, 0x1, 0x1, 0x1, 0x1]))
      strictEqual(packetNumber.flagBits, 0b11)
    })

    it('PacketNumber.flagToByteLen', function () {
      strictEqual(PacketNumber.flagToByteLen(0b00), 1)
      strictEqual(PacketNumber.flagToByteLen(0b01), 2)
      strictEqual(PacketNumber.flagToByteLen(0b10), 4)
      strictEqual(PacketNumber.flagToByteLen(0b11), 6)
    })
  })

  suite('StreamID', function () {
    it('new StreamID', function () {
      throws(() => new StreamID(bufferFromBytes([])))

      let streamID = new StreamID(bufferFromBytes([0x0]))
      strictEqual(streamID.value, 0)
      ok(streamID.toBuffer().equals(bufferFromBytes([0x0])))

      streamID = new StreamID(bufferFromBytes([0x1]))
      strictEqual(streamID.value, 1)
      ok(streamID.toBuffer().equals(bufferFromBytes([0x1])))

      streamID = new StreamID(bufferFromBytes([0x0, 0x1, 0x0, 0x0]))
      strictEqual(streamID.value, 0x100)
      ok(streamID.toBuffer().equals(bufferFromBytes([0x0, 0x1])))

      streamID = new StreamID(bufferFromBytes([0x0, 0x0, 0x1, 0x0]))
      strictEqual(streamID.value, 0x10000)
      ok(streamID.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x1])))

      streamID = new StreamID(bufferFromBytes([0x0, 0x0, 0x1, 0x0, 0x0, 0x0]))
      strictEqual(streamID.value, 0x10000)
      ok(streamID.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x1])))

      streamID = new StreamID(bufferFromBytes([
        0x0, 0x0, 0x0, 0x1,
        0x0, 0x0, 0x0, 0x0
      ]))
      strictEqual(streamID.value, 0x1000000)
      ok(streamID.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x0, 0x1])))

      throws(() => new StreamID(bufferFromBytes([
        0x0, 0x0, 0x0, 0x0,
        0x1, 0x0, 0x0, 0x0
      ])))
    })

    it('StreamID.fromValue', function () {
      let id = 0  // 8 bits
      let streamID = StreamID.fromValue(id)
      strictEqual(streamID.value, id)
      ok(streamID.toBuffer().equals(bufferFromBytes([0x0])))

      id = 1  // 8 bits
      streamID = StreamID.fromValue(id)
      strictEqual(streamID.value, id)
      ok(streamID.toBuffer().equals(bufferFromBytes([0x1])))

      id = 0x100  // 16 bits
      streamID = StreamID.fromValue(id)
      strictEqual(streamID.value, id)
      ok(streamID.toBuffer().equals(bufferFromBytes([0x0, 0x1])))

      id = 0x10000 // 24 bits
      streamID = StreamID.fromValue(id)
      strictEqual(streamID.value, id)
      ok(streamID.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x1])))

      id = 0x1000000 // 32 bits
      streamID = StreamID.fromValue(id)
      strictEqual(streamID.value, id)
      ok(streamID.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x0, 0x1])))

      id = 0x100000000 // > 32 bit
      throws(() => StreamID.fromValue(id))
    })

    it('StreamID.equals', function () {
      ok(StreamID.fromValue(1).equals(new StreamID(bufferFromBytes([0x1]))))
      ok(StreamID.fromValue(0x10000)
        .equals(new StreamID(bufferFromBytes([0x0, 0x0, 0x1, 0x0, 0x0, 0x0]))))
      ok(!StreamID.fromValue(0x10000)
        .equals(new StreamID(bufferFromBytes([0x0, 0x0, 0x0, 0x1, 0x0, 0x0]))))
    })

    it('StreamID.toFullBuffer', function () {
      ok(bufferFromBytes([0x1, 0x0, 0x0, 0x0]).equals(
        new StreamID(bufferFromBytes([0x1])).toFullBuffer()))
      ok(bufferFromBytes([0x0, 0x0, 0x0, 0x1]).equals(
        new StreamID(bufferFromBytes([0x0, 0x0, 0x0, 0x1])).toFullBuffer()))
    })

    it('StreamID.nextID', function () {
      let streamID1 = StreamID.fromValue(1)
      let streamID2 = StreamID.fromValue(2)
      streamID1 = streamID1.nextID()
      strictEqual(streamID1.value, 3)
      strictEqual(streamID1.nextID().value, 5)
      strictEqual(streamID2.nextID().value, 4)
      strictEqual(StreamID.fromValue(0xffffffff).nextID().value, 2)
      strictEqual(StreamID.fromValue(0xffffffff - 1).nextID().value, 1)
    })

    it('streamID.flagBits', function () {
      let streamID = new StreamID(bufferFromBytes([0x1]))
      strictEqual(streamID.flagBits, 0b00)

      streamID = new StreamID(bufferFromBytes([0x1, 0x1]))
      strictEqual(streamID.flagBits, 0b01)

      streamID = new StreamID(bufferFromBytes([0x1, 0x1, 0x1]))
      strictEqual(streamID.flagBits, 0b10)

      streamID = new StreamID(bufferFromBytes([0x1, 0x1, 0x1, 0x1]))
      strictEqual(streamID.flagBits, 0b11)
    })

    it('StreamID.flagToByteLen', function () {
      strictEqual(StreamID.flagToByteLen(0b00), 1)
      strictEqual(StreamID.flagToByteLen(0b01), 2)
      strictEqual(StreamID.flagToByteLen(0b10), 3)
      strictEqual(StreamID.flagToByteLen(0b11), 4)
    })
  })

  suite('SocketAddress', function () {
    it('SocketAddress, IPv4', function () {
      let socketAddress = SocketAddress.fromObject(
        {port: 3000, family: 'IPv4', address: '127.0.0.1'})
      let res = new SocketAddress(socketAddress.toBuffer())
      deepEqual(socketAddress, res)

      socketAddress = SocketAddress.fromObject(
        {port: 0x1234, family: 'IPv4', address: '4.31.198.44'})
      ok(socketAddress.toBuffer().equals(bufferFromBytes([
        0x02, 0x00, 0x04, 0x1f, 0xc6, 0x2c, 0x34, 0x12
      ])))
    })

    it('SocketAddress, IPv6', function () {
      let socketAddress = SocketAddress.fromObject(
        {port: 65534, family: 'IPv6', address: '::1'})
      strictEqual(socketAddress.address, '0:0:0:0:0:0:0:1')
      let res = new SocketAddress(socketAddress.toBuffer())
      deepEqual(socketAddress, res)

      socketAddress = SocketAddress.fromObject({
        port: 0x5678, family: 'IPv6', address: '2001:700:300:1800::'})
      strictEqual(socketAddress.address, '2001:700:300:1800:0:0:0:0')
      res = new SocketAddress(socketAddress.toBuffer())
      deepEqual(socketAddress, res)

      socketAddress = SocketAddress.fromObject({
        port: 0x5678, family: 'IPv6', address: '2001:700:300:1800::f'})
      ok(socketAddress.toBuffer().equals(bufferFromBytes([
        0x0a, 0x00,
        0x20, 0x01, 0x07, 0x00, 0x03, 0x00, 0x18, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
        0x78, 0x56
      ])))
    })
  })

  suite('Offset', function () {
    it('new Offset', function () {
      let offset = new Offset(bufferFromBytes([]))
      strictEqual(offset.value, 0)
      ok(offset.toBuffer().equals(bufferFromBytes([])))

      offset = new Offset(bufferFromBytes([0x1]))
      strictEqual(offset.value, 1)
      ok(offset.toBuffer().equals(bufferFromBytes([0x1, 0x0])))

      offset = new Offset(bufferFromBytes([0x0, 0x1, 0x0, 0x0]))
      strictEqual(offset.value, 0x100)
      ok(offset.toBuffer().equals(bufferFromBytes([0x0, 0x1])))

      offset = new Offset(bufferFromBytes([0x0, 0x0, 0x1, 0x0, 0x0, 0x0]))
      strictEqual(offset.value, 0x10000)
      ok(offset.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x1])))

      offset = new Offset(bufferFromBytes([
        0x0, 0x0, 0x0, 0x0,
        0x1, 0x0, 0x0, 0x0
      ]))
      strictEqual(offset.value, 0x100000000)
      ok(offset.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x1])))

      offset = new Offset(bufferFromBytes([
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x1, 0x0, 0x0
      ]))
      strictEqual(offset.value, 0x010000000000)
      ok(offset.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x0, 0x1])))

      throws(() => new Offset(bufferFromBytes([
        0x0, 0x0, 0x0, 0x0,
        0x1, 0x0, 0x1, 0x0
      ])))
    })

    it('Offset.fromValue', function () {
      let value = 0  // 0 bits
      let offset = Offset.fromValue(value)
      strictEqual(offset.value, 0)
      ok(offset.toBuffer().equals(bufferFromBytes([])))

      value = 1  // 16 bits
      offset = Offset.fromValue(value)
      strictEqual(offset.value, value)
      ok(offset.toBuffer().equals(bufferFromBytes([0x1, 0x0])))

      value = 0x0100  // 16 bits
      offset = Offset.fromValue(value)
      strictEqual(offset.value, value)
      ok(offset.toBuffer().equals(bufferFromBytes([0x0, 0x1])))

      value = 0x010000 // 24 bits
      offset = Offset.fromValue(value)
      strictEqual(offset.value, value)
      ok(offset.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x1])))

      value = 0x01000000 // 32 bits
      offset = Offset.fromValue(value)
      strictEqual(offset.value, value)
      ok(offset.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x0, 0x1])))

      value = 0x0100000000 // 40 bits
      offset = Offset.fromValue(value)
      strictEqual(offset.value, value)
      ok(offset.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x1])))

      value = 0x010000000000 // 48 bits
      offset = Offset.fromValue(value)
      strictEqual(offset.value, value)
      ok(offset.toBuffer().equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x0, 0x1])))

      value = 0x1000000000000 // > 48 bit
      throws(() => Offset.fromValue(value))
    })

    it('offset.toFullBuffer', function () {
      ok(bufferFromBytes([0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]).equals(
        new Offset(bufferFromBytes([0x1])).toFullBuffer()))
      ok(bufferFromBytes([0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0]).equals(
        new Offset(bufferFromBytes([0x0, 0x0, 0x0, 0x1])).toFullBuffer()))
    })

    it('offset.nextOffset', function () {
      let offset = Offset.fromValue(64)
      strictEqual(offset.value, 64)
      offset = offset.nextOffset(64)
      strictEqual(offset.value, 128)
      offset = offset.nextOffset(32)
      strictEqual(offset.value, 160)
    })

    it('offset.flagBits', function () {
      let offset = new Offset(bufferFromBytes([]))
      strictEqual(offset.flagBits, 0b000)

      offset = new Offset(bufferFromBytes([0x1]))
      strictEqual(offset.flagBits, 0b001)

      offset = new Offset(bufferFromBytes([0x1, 0x1]))
      strictEqual(offset.flagBits, 0b001)

      offset = new Offset(bufferFromBytes([0x1, 0x1, 0x1]))
      strictEqual(offset.flagBits, 0b010)

      offset = new Offset(bufferFromBytes([0x1, 0x1, 0x1, 0x1]))
      strictEqual(offset.flagBits, 0b011)

      offset = new Offset(bufferFromBytes([0x1, 0x1, 0x1, 0x1, 0x1]))
      strictEqual(offset.flagBits, 0b100)

      offset = new Offset(bufferFromBytes([0x1, 0x1, 0x1, 0x1, 0x1, 0x1]))
      strictEqual(offset.flagBits, 0b101)
    })

    it('Offset.flagToByteLen', function () {
      strictEqual(Offset.flagToByteLen(0b000), 0)
      strictEqual(Offset.flagToByteLen(0b001), 2)
      strictEqual(Offset.flagToByteLen(0b010), 3)
      strictEqual(Offset.flagToByteLen(0b011), 4)
      strictEqual(Offset.flagToByteLen(0b100), 5)
      strictEqual(Offset.flagToByteLen(0b101), 6)
      strictEqual(Offset.flagToByteLen(0b110), 7)
      strictEqual(Offset.flagToByteLen(0b111), 8)
    })
  })
})
