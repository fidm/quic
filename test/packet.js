'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const tman = require('tman')
const assert = require('assert')
const packet = require('../lib/packet')
const bufferFromBytes = require('../lib/util').bufferFromBytes

tman.suite('packet', function () {
  tman.suite('PacketNumber', function () {
    const PacketNumber = packet.PacketNumber

    tman.it('PacketNumber.fromId', function () {
      let id = 1  // 8 bits
      let packetNumber = PacketNumber.fromId(id)
      assert.strictEqual(packetNumber.id, id)
      assert.ok(packetNumber.buf.equals(bufferFromBytes([0x1])))

      id = 0x100  // 16 bits
      packetNumber = PacketNumber.fromId(id)
      assert.strictEqual(packetNumber.id, id)
      assert.ok(packetNumber.buf.equals(bufferFromBytes([0x0, 0x1])))

      id = 0x10000 // 32 bits
      packetNumber = PacketNumber.fromId(id)
      assert.strictEqual(packetNumber.id, id)
      assert.ok(packetNumber.buf.equals(bufferFromBytes([0x0, 0x0, 0x1, 0x0])))

      id = 0x100000000 // 48 bits
      packetNumber = PacketNumber.fromId(id)
      assert.strictEqual(packetNumber.id, id)
      assert.ok(packetNumber.buf.equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x1, 0x0])))

      id = 0x1000000000000 // > 48 bit
      assert.throws(() => PacketNumber.fromId(id))
    })

    tman.it('PacketNumber.fromBuffer', function () {
      let packetNumber = PacketNumber.fromBuffer(bufferFromBytes([0x1]))
      assert.strictEqual(packetNumber.id, 1)
      assert.ok(packetNumber.buf.equals(bufferFromBytes([0x1])))

      packetNumber = PacketNumber.fromBuffer(bufferFromBytes([0x0, 0x1, 0x0, 0x0]))
      assert.strictEqual(packetNumber.id, 0x100)
      assert.ok(packetNumber.buf.equals(bufferFromBytes([0x0, 0x1])))

      packetNumber = PacketNumber.fromBuffer(bufferFromBytes([0x0, 0x0, 0x1, 0x0, 0x0, 0x0]))
      assert.strictEqual(packetNumber.id, 0x10000)
      assert.ok(packetNumber.buf.equals(bufferFromBytes([0x0, 0x0, 0x1, 0x0])))

      packetNumber = PacketNumber.fromBuffer(bufferFromBytes([
        0x0, 0x0, 0x0, 0x0,
        0x1, 0x0, 0x0, 0x0
      ]))
      assert.strictEqual(packetNumber.id, 0x100000000)
      assert.ok(packetNumber.buf.equals(bufferFromBytes([0x0, 0x0, 0x0, 0x0, 0x1, 0x0])))

      assert.throws(() => PacketNumber.fromBuffer(bufferFromBytes([
        0x0, 0x0, 0x0, 0x0,
        0x1, 0x0, 0x1, 0x0
      ])))
    })

    tman.it('packetNumber.equals', function () {
      assert.ok(PacketNumber.fromId(1).equals(PacketNumber.fromBuffer(bufferFromBytes([0x1]))))
      assert.ok(PacketNumber.fromId(0x10000)
        .equals(PacketNumber.fromBuffer(bufferFromBytes([0x0, 0x0, 0x1, 0x0, 0x0, 0x0]))))
      assert.ok(!PacketNumber.fromId(0x10000)
        .equals(PacketNumber.fromBuffer(bufferFromBytes([0x0, 0x0, 0x0, 0x1, 0x0, 0x0]))))
    })

    tman.it('packetNumber.toBuffer64', function () {
      assert.ok(bufferFromBytes([0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]).equals(
        PacketNumber.fromBuffer(bufferFromBytes([0x1])).toBuffer64()))
      assert.ok(bufferFromBytes([0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0]).equals(
        PacketNumber.fromBuffer(bufferFromBytes([0x0, 0x0, 0x0, 0x1])).toBuffer64()))
    })

    tman.it('packetNumber.nextNumber', function () {
      let packetNumber = PacketNumber.fromId(1)
      packetNumber = packetNumber.nextNumber()
      assert.strictEqual(packetNumber.id, 2)
      assert.strictEqual(packetNumber.nextNumber().id, 3)
      assert.strictEqual(PacketNumber.fromId(0xffffffffff).nextNumber().id, 1)
    })
  })

  // tman.suite('ConnectionId', function () {
  //   const ConnectionId = packet.ConnectionId
  // })
  //
  // tman.suite('ResetPacket', function () {
  //   const ResetPacket = packet.ResetPacket
  // })
  //
  // tman.suite('NegotiationPacket', function () {
  //   const NegotiationPacket = packet.NegotiationPacket
  // })
  //
  // tman.suite('RegularPacket', function () {
  //   const PacketNumber = packet.RegularPacket
  // })
  //
  // tman.suite('Packet', function () {
  //   const PacketNumber = packet.Packet
  // })
})
