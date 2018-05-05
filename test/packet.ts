'use strict'
// **Github:** https://github.com/fidm/quic
//
// **License:** MIT

import { suite, it } from 'tman'
import { ok, equal, deepEqual } from 'assert'

import { toBuffer, BufferVisitor } from '../src/internal/common'
import {
  getVersion, getVersions, isSupportedVersion,
  PacketNumber, ConnectionID, SocketAddress, SessionType, QuicTags, Tag,
} from '../src/internal/protocol'
import {
  parsePacket, ResetPacket, NegotiationPacket,
  RegularPacket,
} from '../src/internal/packet'
import {
  PaddingFrame, PingFrame,
} from '../src/internal/frame'

import { bufferFromBytes } from './common'

suite('QUIC Packet', function () {
  suite('ResetPacket', function () {
    it('fromBuffer and toBuffer', function () {
      const connectionID = ConnectionID.random()
      const quicTag = new QuicTags(Tag.PRST)
      quicTag.set(Tag.RNON, bufferFromBytes([
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB]))
      quicTag.set(Tag.RSEQ, toBuffer(new PacketNumber(1)))
      quicTag.set(Tag.CADR, bufferFromBytes([
        0x00, 0x02,
        0x04, 0x1F, 0xC6, 0x2C,
        0x01, 0xBB]))

      const resetPacket = new ResetPacket(connectionID, quicTag)
      const buf = toBuffer(resetPacket)
      const res = ResetPacket.fromBuffer(new BufferVisitor(buf))
      ok(res instanceof ResetPacket)
      ok(resetPacket.flag === res.flag)
      ok(resetPacket.connectionID.equals(res.connectionID))
      ok(resetPacket.packetNumber.equals(res.packetNumber))
      ok(resetPacket.nonceProof.equals(res.nonceProof))
      ok(resetPacket.socketAddress.equals(res.socketAddress))
    })

    it('parse with parsePacket', function () {
      const connectionID = ConnectionID.random()
      const quicTag = new QuicTags(Tag.PRST)
      quicTag.set(Tag.RNON, bufferFromBytes([
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB]))
      quicTag.set(Tag.RSEQ, toBuffer(new PacketNumber(1)))
      quicTag.set(Tag.CADR, bufferFromBytes([
        0x00, 0x02,
        0x04, 0x1F, 0xC6, 0x2C,
        0x01, 0xBB]))

      const resetPacket = new ResetPacket(connectionID, quicTag)
      const buf = toBuffer(resetPacket)
      const res = parsePacket(new BufferVisitor(buf), SessionType.SERVER) as ResetPacket
      ok(res instanceof ResetPacket)
      ok(resetPacket.flag === res.flag)
      ok(resetPacket.connectionID.equals(res.connectionID))
      ok(resetPacket.packetNumber.equals(res.packetNumber))
      ok(resetPacket.nonceProof.equals(res.nonceProof))
      ok(resetPacket.socketAddress.equals(res.socketAddress))
    })
  })

  suite('NegotiationPacket', function () {
    it('fromBuffer and toBuffer', function () {
      const connectionID = ConnectionID.random()
      const negotiationPacket = NegotiationPacket.fromConnectionID(connectionID)
      deepEqual(negotiationPacket.versions, getVersions())
      ok(isSupportedVersion(negotiationPacket.versions[0]))

      const buf = toBuffer(negotiationPacket)
      const res = NegotiationPacket.fromBuffer(new BufferVisitor(buf))
      ok(res instanceof NegotiationPacket)
      ok(negotiationPacket.flag === res.flag)
      ok(negotiationPacket.connectionID.equals(res.connectionID))
      deepEqual(negotiationPacket.versions, res.versions)
    })

    it('parse with parsePacket', function () {
      const connectionID = ConnectionID.random()
      const negotiationPacket = NegotiationPacket.fromConnectionID(connectionID)
      deepEqual(negotiationPacket.versions, getVersions())
      ok(isSupportedVersion(negotiationPacket.versions[0]))

      const buf = toBuffer(negotiationPacket)
      const res = parsePacket(new BufferVisitor(buf), SessionType.SERVER) as NegotiationPacket
      ok(res instanceof NegotiationPacket)
      ok(negotiationPacket.flag === res.flag)
      ok(negotiationPacket.connectionID.equals(res.connectionID))
      deepEqual(negotiationPacket.versions, res.versions)
    })
  })

  suite('RegularPacket', function () {
    it('fromBuffer and toBuffer', function () {
      const connectionID = ConnectionID.random()
      const packetNumber = new PacketNumber(16)
      const regularPacket = new RegularPacket(connectionID, packetNumber)
      regularPacket.setVersion(getVersion())
      regularPacket.addFrames(new PaddingFrame(), new PingFrame())
      const buf = toBuffer(regularPacket)
      const bufv = new BufferVisitor(buf)
      const res = RegularPacket.fromBuffer(bufv, regularPacket.flag, SessionType.SERVER)

      ok(res instanceof RegularPacket)
      ok(regularPacket.flag === res.flag)
      ok(regularPacket.connectionID.equals(res.connectionID))
      ok(regularPacket.packetNumber.equals(res.packetNumber))
      equal(regularPacket.version, res.version)
      equal(res.frames.length, 0)
      res.parseFrames(bufv)
      equal(res.frames.length, 2)
      equal(res.frames[0].name, 'PADDING')
      equal(res.frames[1].name, 'PING')
    })

    it('parse with parsePacket', function () {
      const connectionID = ConnectionID.random()
      const packetNumber = new PacketNumber(16)
      const regularPacket = new RegularPacket(connectionID, packetNumber)
      regularPacket.setVersion(getVersion())
      regularPacket.addFrames(new PaddingFrame(), new PingFrame())
      const buf = toBuffer(regularPacket)
      const bufv = new BufferVisitor(buf)
      const res = parsePacket(bufv, SessionType.CLIENT) as RegularPacket
      ok(res instanceof RegularPacket)
      ok(regularPacket.flag === res.flag)
      ok(regularPacket.connectionID.equals(res.connectionID))
      ok(regularPacket.packetNumber.equals(res.packetNumber))
      equal(regularPacket.version, res.version)
      equal(res.frames.length, 0)
      res.parseFrames(bufv)
      equal(res.frames.length, 2)
      equal(res.frames[0].name, 'PADDING')
      equal(res.frames[1].name, 'PING')
    })

    it('parse data from chrome', function () {
      let bufv = new BufferVisitor(bufferFromBytes([0x1c, 0xb8, 0xef, 0xb3, 0xf0, 0xa2, 0x16, 0x5e, 0x4c, 0x1, 0xf]))
      let res = parsePacket(bufv, SessionType.CLIENT) as RegularPacket
      ok(res instanceof RegularPacket)
      equal(res.flag, 24)
      equal(res.connectionID.valueOf(), 'b8efb3f0a2165e4c')
      equal(res.packetNumber, 271)
      equal(res.version, '')
      equal(res.frames.length, 0)

      bufv = new BufferVisitor(bufferFromBytes([0x1c, 0xb8, 0xef, 0xb3, 0xf0, 0xa2, 0x16, 0x5e, 0x4c, 0x1, 0x10]))
      res = parsePacket(bufv, SessionType.CLIENT) as RegularPacket
      equal(res.packetNumber, 272)
    })
  })
})
