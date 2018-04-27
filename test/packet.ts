'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

import { suite, it } from 'tman'
import { ok, equal, deepEqual } from 'assert'

import { toBuffer, BufferVisitor } from '../src/internal/common'
import {
  getVersion, getVersions, isSupportedVersion,
  PacketNumber, ConnectionID, SocketAddress, SessionType, QuicTag,
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
      const quicTag = new QuicTag('PRST')
      quicTag.setTag('RNON', bufferFromBytes([
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB]))
      quicTag.setTag('RSEQ', toBuffer(new PacketNumber(1)))
      quicTag.setTag('CADR', bufferFromBytes([
        0x02, 0x00,
        0x04, 0x1F, 0xC6, 0x2C,
        0xBB, 0x01]))

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
      const quicTag = new QuicTag('PRST')
      quicTag.setTag('RNON', bufferFromBytes([
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB]))
      quicTag.setTag('RSEQ', toBuffer(new PacketNumber(1)))
      quicTag.setTag('CADR', bufferFromBytes([
        0x02, 0x00,
        0x04, 0x1F, 0xC6, 0x2C,
        0xBB, 0x01]))

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
      const nonceProof = bufferFromBytes([
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB])

      const regularPacket = new RegularPacket(connectionID, packetNumber, nonceProof)
      regularPacket.setVersion(getVersion())
      regularPacket.addFrames(new PaddingFrame(), new PingFrame())
      const buf = toBuffer(regularPacket)
      const res = RegularPacket.fromBuffer(new BufferVisitor(buf), regularPacket.flag)
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
      const connectionID = ConnectionID.random()
      const packetNumber = new PacketNumber(16)
      const nonceProof = bufferFromBytes([
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB,
        0x89, 0x67, 0x45, 0x23,
        0x01, 0xEF, 0xCD, 0xAB])

      const regularPacket = new RegularPacket(connectionID, packetNumber, nonceProof)
      regularPacket.setVersion(getVersion())
      regularPacket.addFrames(new PaddingFrame(), new PingFrame())
      const buf = toBuffer(regularPacket)
      const res = parsePacket(new BufferVisitor(buf), SessionType.CLIENT) as RegularPacket
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
