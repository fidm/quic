'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const { suite, it } = require('tman')
const { ok, equal, deepEqual } = require('assert')

const { Visitor } = require('../lib/common')
const { bufferFromBytes } = require('./common')

const {
  getVersion, getVersions, isSupportedVersion,
  PacketNumber, ConnectionID, SocketAddress, QUIC_SERVER, QUIC_CLIENT
} = require('../lib/protocol')

const {
  parsePacket, ResetPacket, NegotiationPacket,
  RegularPacket
} = require('../lib/packet')

const {
  PaddingFrame, PingFrame
} = require('../lib/frame')

suite('QUIC Packet', function () {
  suite('ResetPacket', function () {
    it('fromBuffer and toBuffer', function () {
      let connectionID = ConnectionID.random()
      let nonceProof = bufferFromBytes([
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
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
      let res = ResetPacket.fromBuffer(Visitor.wrap(buf))
      ok(res instanceof ResetPacket)
      ok(resetPacket.flag === res.flag)
      ok(resetPacket.connectionID.equals(res.connectionID))
      ok(resetPacket.packetNumber.equals(res.packetNumber))
      ok(resetPacket.nonceProof.equals(res.nonceProof))
      deepEqual(resetPacket.socketAddress, res.socketAddress)
    })

    it('parse with parsePacket', function () {
      let connectionID = ConnectionID.random()
      let nonceProof = bufferFromBytes([
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
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

  suite('NegotiationPacket', function () {
    it('fromBuffer and toBuffer', function () {
      let connectionID = ConnectionID.random()
      let negotiationPacket = NegotiationPacket.fromConnectionID(connectionID)
      deepEqual(negotiationPacket.versions, getVersions())
      ok(isSupportedVersion(negotiationPacket.versions[0]))

      let buf = negotiationPacket.toBuffer()
      let res = NegotiationPacket.fromBuffer(Visitor.wrap(buf))
      ok(res instanceof NegotiationPacket)
      ok(negotiationPacket.flag === res.flag)
      ok(negotiationPacket.connectionID.equals(res.connectionID))
      deepEqual(negotiationPacket.versions, res.versions)
    })

    it('parse with parsePacket', function () {
      let connectionID = ConnectionID.random()
      let negotiationPacket = NegotiationPacket.fromConnectionID(connectionID)
      deepEqual(negotiationPacket.versions, getVersions())
      ok(isSupportedVersion(negotiationPacket.versions[0]))

      let buf = negotiationPacket.toBuffer()
      let res = parsePacket(Visitor.wrap(buf), QUIC_SERVER)
      ok(res instanceof NegotiationPacket)
      ok(negotiationPacket.flag === res.flag)
      ok(negotiationPacket.connectionID.equals(res.connectionID))
      deepEqual(negotiationPacket.versions, res.versions)
    })
  })

  suite('RegularPacket', function () {
    it('fromBuffer and toBuffer', function () {
      let connectionID = ConnectionID.random()
      let packetNumber = PacketNumber.fromValue(16)
      let nonceProof = bufferFromBytes([
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB
      ])

      let regularPacket = new RegularPacket(connectionID, packetNumber, nonceProof, getVersion())
      regularPacket.addFrames(new PaddingFrame(), new PingFrame())
      let buf = regularPacket.toBuffer()
      let res = RegularPacket.fromBuffer(Visitor.wrap(buf), regularPacket.flag)
      ok(res instanceof RegularPacket)
      ok(regularPacket.flag === res.flag)
      ok(regularPacket.connectionID.equals(res.connectionID))
      ok(regularPacket.packetNumber.equals(res.packetNumber))
      ok(regularPacket.nonce.equals(res.nonce))
      equal(regularPacket.version, res.version)
      equal(res.frames[0].name, 'PADDING')
      equal(res.frames[1].name, 'PING')
    })

    it('parse with parsePacket', function () {
      let connectionID = ConnectionID.random()
      let packetNumber = PacketNumber.fromValue(16)
      let nonceProof = bufferFromBytes([
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB
      ])

      let regularPacket = new RegularPacket(connectionID, packetNumber, nonceProof, getVersion())
      regularPacket.addFrames(new PaddingFrame(), new PingFrame())
      let buf = regularPacket.toBuffer()
      let res = parsePacket(Visitor.wrap(buf), QUIC_CLIENT)
      ok(res instanceof RegularPacket)
      ok(regularPacket.flag === res.flag)
      ok(regularPacket.connectionID.equals(res.connectionID))
      ok(regularPacket.packetNumber.equals(res.packetNumber))
      ok(regularPacket.nonce.equals(res.nonce))
      equal(regularPacket.version, res.version)
      equal(res.frames[0].name, 'PADDING')
      equal(res.frames[1].name, 'PING')
    })
  })
})
