'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

import { suite, it } from 'tman'
import { ok, strictEqual, deepEqual, throws, equal } from 'assert'

import {
  ConnectionID, PacketNumber, StreamID, SocketAddress, Offset, QuicTag,
} from '../src/internal/protocol'
import { Visitor, toBuffer } from '../src/internal/common'

import { bufferFromBytes } from './common'

suite('QUIC Protocol', function () {
  suite('ConnectionID', function () {
    it('ConnectionID.random, ConnectionID.fromString', function () {
      const connectionID = ConnectionID.random()
      strictEqual(connectionID.byteLen(), 8)
      strictEqual(connectionID.valueOf().length, 16)
      ok(connectionID.equals(new ConnectionID(connectionID.toString())))
      ok(connectionID.equals(ConnectionID.fromBuffer(toBuffer(connectionID))))
    })
  })

  suite('PacketNumber', function () {
    it('PacketNumber.fromBuffer', function () {
      throws(() => PacketNumber.fromBuffer(bufferFromBytes([]), 0))
      let packetNumber = PacketNumber.fromBuffer(bufferFromBytes([0x1]), 1)
      strictEqual(packetNumber.valueOf(), 1)
      ok(toBuffer(packetNumber).equals(bufferFromBytes([0x1])))

      packetNumber = PacketNumber.fromBuffer(bufferFromBytes([0x0, 0x1, 0x0, 0x0]), 4)
      strictEqual(packetNumber.valueOf(), 0x100)
      ok(toBuffer(packetNumber).equals(bufferFromBytes([0x0, 0x1])))

      packetNumber = PacketNumber.fromBuffer(bufferFromBytes([0x0, 0x0, 0x1, 0x0]), 4)
      strictEqual(packetNumber.valueOf(), 0x10000)
      ok(toBuffer(packetNumber).equals(bufferFromBytes([0x0, 0x0, 0x1, 0x0])))

      packetNumber = PacketNumber.fromBuffer(bufferFromBytes([0x0, 0x0, 0x1, 0x0, 0x0, 0x0]), 6)
      strictEqual(packetNumber.valueOf(), 0x10000)
      ok(toBuffer(packetNumber).equals(bufferFromBytes([0x0, 0x0, 0x1, 0x0])))

      packetNumber = PacketNumber.fromBuffer(bufferFromBytes([
        0x0, 0x0, 0x0, 0x0,
        0x1, 0x0, 0x0, 0x0]), 8)
      strictEqual(packetNumber.valueOf(), 0x100000000)
      ok(toBuffer(packetNumber).equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x1, 0x0])))

      throws(() => PacketNumber.fromBuffer(bufferFromBytes([
        0x0, 0x0, 0x0, 0x0,
        0x1, 0x0, 0x1, 0x0]), 8))
    })

    it('new PacketNumber', function () {
      throws(() => new PacketNumber(0))

      let id = 1  // 8 bits
      let packetNumber = new PacketNumber(id)
      strictEqual(packetNumber.valueOf(), id)
      ok(toBuffer(packetNumber).equals(bufferFromBytes([0x1])))

      id = 0x100  // 16 bits
      packetNumber = new PacketNumber(id)
      strictEqual(packetNumber.valueOf(), id)
      ok(toBuffer(packetNumber).equals(bufferFromBytes([0x0, 0x1])))

      id = 0x10000 // 32 bits
      packetNumber = new PacketNumber(id)
      strictEqual(packetNumber.valueOf(), id)
      ok(toBuffer(packetNumber).equals(bufferFromBytes([0x0, 0x0, 0x1, 0x0])))

      id = 0x100000000 // 48 bits
      packetNumber = new PacketNumber(id)
      strictEqual(packetNumber.valueOf(), id)
      ok(toBuffer(packetNumber).equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x1, 0x0])))

      id = 0x1000000000000 // > 48 bit
      throws(() => new PacketNumber(id))
    })

    it('packetNumber.equals', function () {
      ok(new PacketNumber(1).equals(PacketNumber.fromBuffer(bufferFromBytes([0x1]), 1)))
      ok(new PacketNumber(0x10000)
        .equals(PacketNumber.fromBuffer(bufferFromBytes([0x0, 0x0, 0x1, 0x0, 0x0, 0x0]), 6)))
      ok(!new PacketNumber(0x10000)
        .equals(PacketNumber.fromBuffer(bufferFromBytes([0x0, 0x0, 0x0, 0x1, 0x0, 0x0]), 6)))
    })

    it('packetNumber.byteLen', function () {
      equal(new PacketNumber(1).byteLen(), 1)
      equal(new PacketNumber(1).byteLen(true), 6)
    })

    it('packetNumber.nextNumber', function () {
      let packetNumber = new PacketNumber(1)
      packetNumber = packetNumber.nextNumber()
      strictEqual(packetNumber.isLimitReached(), false)
      strictEqual(packetNumber.valueOf(), 2)
      strictEqual(packetNumber.nextNumber().valueOf(), 3)

      packetNumber = new PacketNumber(0xffffffffffff - 1)
      strictEqual(packetNumber.isLimitReached(), false)
      packetNumber = packetNumber.nextNumber()
      strictEqual(packetNumber.isLimitReached(), true)
      throws(() => packetNumber = packetNumber.nextNumber())
    })

    it('packetNumber.flagBits()', function () {
      let packetNumber = PacketNumber.fromBuffer(bufferFromBytes([0x1]), 1)
      strictEqual(packetNumber.flagBits(), 0b00)

      packetNumber = PacketNumber.fromBuffer(bufferFromBytes([0x1, 0x1]), 2)
      strictEqual(packetNumber.flagBits(), 0b01)

      packetNumber = PacketNumber.fromBuffer(bufferFromBytes([0x1, 0x1, 0x1]), 3)
      strictEqual(packetNumber.flagBits(), 0b10)
      packetNumber = PacketNumber.fromBuffer(bufferFromBytes([0x1, 0x1, 0x1, 0x1]), 4)
      strictEqual(packetNumber.flagBits(), 0b10)

      packetNumber = PacketNumber.fromBuffer(bufferFromBytes([0x1, 0x1, 0x1, 0x1, 0x1]), 5)
      strictEqual(packetNumber.flagBits(), 0b11)
      packetNumber = PacketNumber.fromBuffer(bufferFromBytes([0x1, 0x1, 0x1, 0x1, 0x1, 0x1]), 6)
      strictEqual(packetNumber.flagBits(), 0b11)
    })

    it('PacketNumber.flagToByteLen', function () {
      strictEqual(PacketNumber.flagToByteLen(0b00), 1)
      strictEqual(PacketNumber.flagToByteLen(0b01), 2)
      strictEqual(PacketNumber.flagToByteLen(0b10), 4)
      strictEqual(PacketNumber.flagToByteLen(0b11), 6)
    })
  })

  suite('StreamID', function () {
    it('StreamID.fromBuffer', function () {
      throws(() => StreamID.fromBuffer(bufferFromBytes([]), 0))

      let streamID = StreamID.fromBuffer(bufferFromBytes([0x0]), 1)
      strictEqual(streamID.valueOf(), 0)
      ok(toBuffer(streamID).equals(bufferFromBytes([0x0])))

      streamID = StreamID.fromBuffer(bufferFromBytes([0x1]), 1)
      strictEqual(streamID.valueOf(), 1)
      ok(toBuffer(streamID).equals(bufferFromBytes([0x1])))

      streamID = StreamID.fromBuffer(bufferFromBytes([0x0, 0x1, 0x0, 0x0]), 4)
      strictEqual(streamID.valueOf(), 0x100)
      ok(toBuffer(streamID).equals(bufferFromBytes([0x0, 0x1])))

      streamID = StreamID.fromBuffer(bufferFromBytes([0x0, 0x0, 0x1, 0x0]), 4)
      strictEqual(streamID.valueOf(), 0x10000)
      ok(toBuffer(streamID).equals(bufferFromBytes([0x0, 0x0, 0x1])))

      streamID = StreamID.fromBuffer(bufferFromBytes([0x0, 0x0, 0x1, 0x0, 0x0, 0x0]), 6)
      strictEqual(streamID.valueOf(), 0x10000)
      ok(toBuffer(streamID).equals(bufferFromBytes([0x0, 0x0, 0x1])))

      streamID = StreamID.fromBuffer(bufferFromBytes([
        0x0, 0x0, 0x0, 0x1,
        0x0, 0x0, 0x0, 0x0]), 8)
      strictEqual(streamID.valueOf(), 0x1000000)
      ok(toBuffer(streamID).equals(bufferFromBytes([0x0, 0x0, 0x0, 0x1])))

      throws(() => StreamID.fromBuffer(bufferFromBytes([
        0x0, 0x0, 0x0, 0x0,
        0x1, 0x0, 0x0, 0x0]), 8))
    })

    it('new StreamID', function () {
      throws(() => new StreamID(-1))

      let id = 0  // 8 bits
      let streamID = new StreamID(id)
      strictEqual(streamID.valueOf(), id)
      ok(toBuffer(streamID).equals(bufferFromBytes([0x0])))

      id = 1  // 8 bits
      streamID = new StreamID(id)
      strictEqual(streamID.valueOf(), id)
      ok(toBuffer(streamID).equals(bufferFromBytes([0x1])))

      id = 0x100  // 16 bits
      streamID = new StreamID(id)
      strictEqual(streamID.valueOf(), id)
      ok(toBuffer(streamID).equals(bufferFromBytes([0x0, 0x1])))

      id = 0x10000 // 24 bits
      streamID = new StreamID(id)
      strictEqual(streamID.valueOf(), id)
      ok(toBuffer(streamID).equals(bufferFromBytes([0x0, 0x0, 0x1])))

      id = 0x1000000 // 32 bits
      streamID = new StreamID(id)
      strictEqual(streamID.valueOf(), id)
      ok(toBuffer(streamID).equals(bufferFromBytes([0x0, 0x0, 0x0, 0x1])))

      id = 0x100000000 // > 32 bit
      throws(() => new StreamID(id))
    })

    it('StreamID.equals', function () {
      ok(new StreamID(1).equals(StreamID.fromBuffer(bufferFromBytes([0x1]), 1)))
      ok(new StreamID(0x10000)
        .equals(StreamID.fromBuffer(bufferFromBytes([0x0, 0x0, 0x1, 0x0, 0x0, 0x0]), 6)))
      ok(!new StreamID(0x10000)
        .equals(StreamID.fromBuffer(bufferFromBytes([0x0, 0x0, 0x0, 0x1, 0x0, 0x0]), 6)))
    })

    it('StreamID.byteLen', function () {
      equal(new StreamID(1).byteLen(), 1)
      equal(new StreamID(1).byteLen(true), 4)
    })

    it('StreamID.nextID', function () {
      let streamID1 = new StreamID(1)
      const streamID2 = new StreamID(2)
      streamID1 = streamID1.nextID()
      strictEqual(streamID1.valueOf(), 3)
      strictEqual(streamID1.nextID().valueOf(), 5)
      strictEqual(streamID2.nextID().valueOf(), 4)
      strictEqual(new StreamID(0xffffffff).nextID().valueOf(), 2)
      strictEqual(new StreamID(0xffffffff - 1).nextID().valueOf(), 1)
    })

    it('streamID.flagBits()', function () {
      let streamID = StreamID.fromBuffer(bufferFromBytes([0x1]), 1)
      strictEqual(streamID.flagBits(), 0b00)

      streamID = StreamID.fromBuffer(bufferFromBytes([0x1, 0x1]), 2)
      strictEqual(streamID.flagBits(), 0b01)

      streamID = StreamID.fromBuffer(bufferFromBytes([0x1, 0x1, 0x1]), 3)
      strictEqual(streamID.flagBits(), 0b10)

      streamID = StreamID.fromBuffer(bufferFromBytes([0x1, 0x1, 0x1, 0x1]), 4)
      strictEqual(streamID.flagBits(), 0b11)
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
      let socketAddress = new SocketAddress(
        { port: 3000, family: 'IPv4', address: '127.0.0.1' })
      const res = SocketAddress.fromBuffer(toBuffer(socketAddress))
      ok(socketAddress.equals(res))

      socketAddress = new SocketAddress(
        { port: 0x1234, family: 'IPv4', address: '4.31.198.44' })
      ok(toBuffer(socketAddress).equals(bufferFromBytes([
        0x02, 0x00, 0x04, 0x1f, 0xc6, 0x2c, 0x34, 0x12])))
    })

    it('SocketAddress, IPv6', function () {
      let socketAddress = new SocketAddress(
        { port: 65534, family: 'IPv6', address: '::1' })
      strictEqual(socketAddress.address, '0:0:0:0:0:0:0:1')
      const res = SocketAddress.fromBuffer(toBuffer(socketAddress))
      ok(socketAddress.equals(res))

      socketAddress = new SocketAddress({
        address: '2001:700:300:1800::', family: 'IPv6', port: 0x5678})
      strictEqual(socketAddress.address, '2001:700:300:1800:0:0:0:0')
      ok(socketAddress.equals(SocketAddress.fromBuffer(toBuffer(socketAddress))))

      socketAddress = new SocketAddress({
        address: '2001:700:300:1800::f', family: 'IPv6', port: 0x5678})
      ok(toBuffer(socketAddress).equals(bufferFromBytes([
        0x0a, 0x00,
        0x20, 0x01, 0x07, 0x00, 0x03, 0x00, 0x18, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
        0x78, 0x56])))
    })
  })

  suite('Offset', function () {
    it('Offset.fromBuffer', function () {
      let offset = Offset.fromBuffer(bufferFromBytes([]), 0)
      strictEqual(offset.valueOf(), 0)
      ok(toBuffer(offset).equals(bufferFromBytes([])))

      offset = Offset.fromBuffer(bufferFromBytes([0x1]), 1)
      strictEqual(offset.valueOf(), 1)
      ok(toBuffer(offset).equals(bufferFromBytes([0x1, 0x0])))

      offset = Offset.fromBuffer(bufferFromBytes([0x0, 0x1, 0x0, 0x0]), 4)
      strictEqual(offset.valueOf(), 0x100)
      ok(toBuffer(offset).equals(bufferFromBytes([0x0, 0x1])))

      offset = Offset.fromBuffer(bufferFromBytes([0x0, 0x0, 0x1, 0x0, 0x0, 0x0]), 6)
      strictEqual(offset.valueOf(), 0x10000)
      ok(toBuffer(offset).equals(bufferFromBytes([0x0, 0x0, 0x1])))

      offset = Offset.fromBuffer(bufferFromBytes([
        0x0, 0x0, 0x0, 0x0,
        0x1, 0x0, 0x0, 0x0]), 8)
      strictEqual(offset.valueOf(), 0x100000000)
      ok(toBuffer(offset).equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x1])))

      offset = Offset.fromBuffer(bufferFromBytes([
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x1, 0x0, 0x0]), 8)
      strictEqual(offset.valueOf(), 0x010000000000)
      ok(toBuffer(offset).equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x0, 0x1])))

      throws(() => Offset.fromBuffer(bufferFromBytes([
        0x0, 0x0, 0x0, 0x0,
        0x1, 0x0, 0x0, 0x1]), 8))
    })

    it('new Offset', function () {
      let value = 0  // 0 bits
      let offset = new Offset(value)
      strictEqual(offset.valueOf(), 0)
      ok(toBuffer(offset).equals(bufferFromBytes([])))

      value = 1  // 16 bits
      offset = new Offset(value)
      strictEqual(offset.valueOf(), value)
      ok(toBuffer(offset).equals(bufferFromBytes([0x1, 0x0])))

      value = 0x0100  // 16 bits
      offset = new Offset(value)
      strictEqual(offset.valueOf(), value)
      ok(toBuffer(offset).equals(bufferFromBytes([0x0, 0x1])))

      value = 0x010000 // 24 bits
      offset = new Offset(value)
      strictEqual(offset.valueOf(), value)
      ok(toBuffer(offset).equals(bufferFromBytes([0x0, 0x0, 0x1])))

      value = 0x01000000 // 32 bits
      offset = new Offset(value)
      strictEqual(offset.valueOf(), value)
      ok(toBuffer(offset).equals(bufferFromBytes([0x0, 0x0, 0x0, 0x1])))

      value = 0x0100000000 // 40 bits
      offset = new Offset(value)
      strictEqual(offset.valueOf(), value)
      ok(toBuffer(offset).equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x1])))

      value = 0x010000000000 // 48 bits
      offset = new Offset(value)
      strictEqual(offset.valueOf(), value)
      ok(toBuffer(offset).equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x0, 0x1])))

      value = 0x100000000000000 // > MaxOffset
      throws(() => new Offset(value))
    })

    it('offset.byteLen', function () {
      equal(new Offset(1).byteLen(), 2)
      equal(new Offset(1).byteLen(true), 8)
      equal(new Offset(0).byteLen(true), 8)
    })

    it('offset.flagBits()', function () {
      let offset = Offset.fromBuffer(bufferFromBytes([]), 0)
      strictEqual(offset.flagBits(), 0b000)

      offset = Offset.fromBuffer(bufferFromBytes([0x1]), 1)
      strictEqual(offset.flagBits(), 0b001)

      offset = Offset.fromBuffer(bufferFromBytes([0x1, 0x1]), 2)
      strictEqual(offset.flagBits(), 0b001)

      offset = Offset.fromBuffer(bufferFromBytes([0x1, 0x1, 0x1]), 3)
      strictEqual(offset.flagBits(), 0b010)

      offset = Offset.fromBuffer(bufferFromBytes([0x1, 0x1, 0x1, 0x1]), 4)
      strictEqual(offset.flagBits(), 0b011)

      offset = Offset.fromBuffer(bufferFromBytes([0x1, 0x1, 0x1, 0x1, 0x1]), 5)
      strictEqual(offset.flagBits(), 0b100)

      offset = Offset.fromBuffer(bufferFromBytes([0x1, 0x1, 0x1, 0x1, 0x1, 0x1]), 6)
      strictEqual(offset.flagBits(), 0b101)
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

  suite('QUIC Tag', function () {
    const data = bufferFromBytes([
      // message tag (kPRST)
      'PRST',
      // num_entries (2) + padding
      0x03, 0x00, 0x00, 0x00,
      // tag kRNON
      'RNON',
      // end offset 8
      0x08, 0x00, 0x00, 0x00,
      // tag kRSEQ
      'RSEQ',
      // end offset 16
      0x10, 0x00, 0x00, 0x00,
      'CADR',
      // end offset 24
      0x18, 0x00, 0x00, 0x00,
      // nonce proof
      0x89, 0x67, 0x45, 0x23,
      0x01, 0xEF, 0xCD, 0xAB,
      // rejected packet number
      0xBC, 0x9A, 0x78, 0x56,
      0x34, 0x12, 0x00, 0x00,
      // client address
      0x02, 0x00,
      0x04, 0x1F, 0xC6, 0x2C,
      0xBB, 0x01])

    it('new QuicTag', function () {
      const quicTag = new QuicTag('PRST')
      quicTag.setTag('RNON', bufferFromBytes([
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB]))

      quicTag.setTag('RSEQ', bufferFromBytes([
        0xBC, 0x9A, 0x78, 0x56,
        0x34, 0x12, 0x00, 0x00]))

      quicTag.setTag('CADR', bufferFromBytes([
        0x02, 0x00,
        0x04, 0x1F, 0xC6, 0x2C,
        0xBB, 0x01]))

      const bufv = Visitor.wrap(Buffer.alloc(quicTag.byteLen()))
      quicTag.writeTo(bufv)
      ok(data.equals(bufv))
    })

    it('QuicTag.fromBuffer', function () {
      const buf = data.slice()
      const quicTag = QuicTag.fromBuffer(Visitor.wrap(buf))
      strictEqual(quicTag.name, 'PRST')
      deepEqual(quicTag.keys, ['RNON', 'RSEQ', 'CADR'])

      let tag = quicTag.getTag('RNON')
      ok(tag && tag.equals(bufferFromBytes([
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB])))
      tag = quicTag.getTag('RSEQ')
      ok(tag && tag.equals(bufferFromBytes([
        0xBC, 0x9A, 0x78, 0x56,
        0x34, 0x12, 0x00, 0x00])))
      tag = quicTag.getTag('CADR')
      ok(tag && tag.equals(bufferFromBytes([
        0x02, 0x00,
        0x04, 0x1F, 0xC6, 0x2C,
        0xBB, 0x01])))

      const bufv = Visitor.wrap(Buffer.alloc(8 + quicTag.byteLen()))
      bufv.v.walk(4)
      quicTag.writeTo(bufv)
      const empty4 = bufferFromBytes([0x0, 0x0, 0x0, 0x0])
      ok(empty4.equals(bufv.slice(0, 4)))
      ok(empty4.equals(bufv.slice(bufv.v.end)))
      bufv.v.reset(4, 4)

      const quicTag2 = QuicTag.fromBuffer(bufv)
      ok(quicTag.equals(quicTag2))
      ok(data.equals(toBuffer(quicTag2)))
    })
  })
})
