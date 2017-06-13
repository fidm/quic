'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const {suite, it} = require('tman')
const {ok, deepEqual} = require('assert')

const QuicId = require('../lib/id')
const QuicPacket = require('../lib/packet')
const bufferFromBytes = require('./util').bufferFromBytes

suite('QuicPacket', function () {
  suite('ResetPacket and parse', function () {
    const ResetPacket = QuicPacket.ResetPacket

    it('new ResetPacket and parse resetPacket buf', function () {
      let connectionID = QuicId.ConnectionID.random()
      let nonceProof = bufferFromBytes([
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB
      ])
      let packetNumber = QuicId.PacketNumber.fromValue(1)
      let socketAddress = new QuicId.SocketAddress(bufferFromBytes([
        0x02, 0x00,
        0x04, 0x1F, 0xC6, 0x2C,
        0xBB, 0x01
      ]))
      let resetPacket = new ResetPacket(connectionID, nonceProof, packetNumber, socketAddress)
      ok(resetPacket instanceof QuicPacket)

      let buf = resetPacket.toBuffer()
      let res = QuicPacket.fromBuffer(buf, true)
      ok(res instanceof QuicPacket)
      ok(resetPacket.flag === res.flag)
      ok(resetPacket.connectionID.equals(res.connectionID))
      ok(resetPacket.packetNumber.equals(res.packetNumber))
      ok(resetPacket.nonceProof.equals(res.nonceProof))
      deepEqual(resetPacket.socketAddress, res.socketAddress)
    })
  })

  suite('NegotiationPacket and parse', function () {
    const NegotiationPacket = QuicPacket.NegotiationPacket

    it('new NegotiationPacket and parse negotiationPacket buf', function () {
      let connectionID = QuicId.ConnectionID.random()
      let negotiationPacket = NegotiationPacket.fromConnectionID(connectionID)
      ok(negotiationPacket instanceof QuicPacket)
      deepEqual(negotiationPacket.versions, QuicPacket.QUIC_VERSIONS)
      ok(QuicPacket.isValidVersion(negotiationPacket.versions[0]))

      let buf = negotiationPacket.toBuffer()
      let res = QuicPacket.fromBuffer(buf, true)
      ok(res instanceof QuicPacket)
      ok(negotiationPacket.flag === res.flag)
      ok(negotiationPacket.connectionID.equals(res.connectionID))
      deepEqual(negotiationPacket.versions, res.versions)
    })
  })

  // suite('RegularPacket', function () {
  //   const PacketNumber = QuicPacket.RegularPacket
  // })
  //
  // suite('Packet', function () {
  //   const PacketNumber = QuicPacket.QuicPacket
  // })
})
