'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const tman = require('tman')
const assert = require('assert')
const QuicId = require('../lib/id')
const QuicPacket = require('../lib/packet')
const bufferFromBytes = require('./util').bufferFromBytes

tman.suite('QuicPacket', function () {
  tman.suite('ResetPacket and parse', function () {
    const ResetPacket = QuicPacket.ResetPacket

    tman.it('new ResetPacket and parse resetPacket buf', function () {
      let connectionId = QuicId.ConnectionID.random()
      let nonceProof = bufferFromBytes([
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB
      ])
      let packetNumber = QuicId.PacketNumber.fromId(1)
      let socketAddress = new QuicId.SocketAddress(bufferFromBytes([
        0x02, 0x00,
        0x04, 0x1F, 0xC6, 0x2C,
        0xBB, 0x01
      ]))
      let resetPacket = new ResetPacket(connectionId, nonceProof, packetNumber, socketAddress)
      assert.ok(resetPacket instanceof QuicPacket)

      let buf = resetPacket.toBuffer()
      let res = QuicPacket.fromBuffer(buf, true)
      assert.ok(res instanceof QuicPacket)
      assert.ok(resetPacket.flag === res.flag)
      assert.ok(resetPacket.connectionId.equals(res.connectionId))
      assert.ok(resetPacket.packetNumber.equals(res.packetNumber))
      assert.ok(resetPacket.nonceProof.equals(res.nonceProof))
      assert.deepEqual(resetPacket.socketAddress, res.socketAddress)
    })
  })

  tman.suite('NegotiationPacket and parse', function () {
    const NegotiationPacket = QuicPacket.NegotiationPacket

    tman.it('new NegotiationPacket and parse negotiationPacket buf', function () {
      let connectionId = QuicId.ConnectionID.random()
      let negotiationPacket = NegotiationPacket.fromConnectionID(connectionId)
      assert.ok(negotiationPacket instanceof QuicPacket)
      assert.deepEqual(negotiationPacket.versions, QuicPacket.QUIC_VERSIONS)
      assert.ok(QuicPacket.isValidVersion(negotiationPacket.versions[0]))

      let buf = negotiationPacket.toBuffer()
      let res = QuicPacket.fromBuffer(buf, true)
      assert.ok(res instanceof QuicPacket)
      assert.ok(negotiationPacket.flag === res.flag)
      assert.ok(negotiationPacket.connectionId.equals(res.connectionId))
      assert.deepEqual(negotiationPacket.versions, res.versions)
    })
  })

  // tman.suite('RegularPacket', function () {
  //   const PacketNumber = QuicPacket.RegularPacket
  // })
  //
  // tman.suite('Packet', function () {
  //   const PacketNumber = QuicPacket.QuicPacket
  // })
})
