'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const { suite, it } = require('tman')
const { ok, deepEqual } = require('assert')

const { Visitor } = require('../lib/common')
const { getVersion, getVersions, isSupportedVersion, PacketNumber, ConnectionID, SocketAddress, QUIC_SERVER } = require('../lib/protocol')
const { parsePacket, ResetPacket, NegotiationPacket } = require('../lib/packet')
const { bufferFromBytes } = require('./common')

suite('QUIC Packet', function () {
  suite('ResetPacket and parse', function () {
    it('new ResetPacket and parse resetPacket buf', function () {
      let connectionID = ConnectionID.random()
      let nonceProof = bufferFromBytes([
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB
      ])
      let packetNumber = PacketNumber.fromValue(1)
      let socketAddress = new SocketAddress(bufferFromBytes([
        0x02, 0x00,
        0x04, 0x1F, 0xC6, 0x2C,
        0xBB, 0x01
      ]))
      let resetPacket = new ResetPacket(connectionID, nonceProof, packetNumber, socketAddress)

      let buf = resetPacket.toBuffer()
      let res = parsePacket(Visitor.wrap(buf), false)
      ok(res instanceof ResetPacket)
      ok(resetPacket.flag === res.flag)
      ok(resetPacket.connectionID.equals(res.connectionID))
      ok(resetPacket.packetNumber.equals(res.packetNumber))
      ok(resetPacket.nonceProof.equals(res.nonceProof))
      deepEqual(resetPacket.socketAddress, res.socketAddress)
    })
  })

  suite('NegotiationPacket and parse', function () {
    it('new NegotiationPacket and parse negotiationPacket buf', function () {
      let connectionID = ConnectionID.random()
      let negotiationPacket = NegotiationPacket.fromConnectionID(connectionID)
      deepEqual(negotiationPacket.versions, getVersions())
      ok(isSupportedVersion(negotiationPacket.versions[0]))

      let buf = negotiationPacket.toBuffer()
      let res = parsePacket(Visitor.wrap(buf), QUIC_SERVER, getVersion())
      ok(res instanceof NegotiationPacket)
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
