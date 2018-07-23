'use strict'
// **Github:** https://github.com/fidm/quic
//
// **License:** MIT

// https://docs.google.com/document/d/1g5nIXAIkN_Y-7XJW5K45IblHd_L2f5LTaDUDwvZ5L6g/edit#

import { isIP } from 'net'
import { randomBytes } from 'crypto'
import { EventEmitter } from 'events'
import { Certificate } from '@fidm/x509'

import { Tag, QuicTags } from './internal/protocol'
import { BufferVisitor } from './internal/common'
import { RegularPacket } from './internal/packet'
import { StreamFrame } from './internal/frame'
import { QuicError } from './internal/error'
import { MinInitialPacketSize } from './internal/constant'
import { kSession, kVersion } from './internal/symbol'
import { fnv1a64Hash, SourceToken } from './internal/crypto'
import { Stream, SessionRef } from './stream'

const ivLen = 12

export class SCFGCache extends Map<string, ServerConfig> {
  constructor () {
    super()
  }
}

export class ServerConfig extends QuicTags {
  // static fromBuffer (bufv: BufferVisitor, cert: Certificate): ServerConfig {
  //   const quicTags = QuicTags.fromBuffer(bufv)
  //   const scfg = new ServerConfig(cert)
  //   scfg.tags = quicTags.tags
  //   scfg.decodeTags()
  //   return scfg
  // }

  id: string // hex, 16-byte
  kexs: string[] // ['C255', 'P256']
  aead: string[]
  vers: string[]
  orbt: string // hex, 8-byte
  expy: number // 64-bit expiry time
  pubs: Buffer[]
  cert: Certificate
  constructor (cert: Certificate) {
    super(Tag.SCFG)
    this.id = ''
    this.pubs = []
    this.expy = 0
    this.orbt = ''
    this.kexs = ['C255'] // Curve25519, P256 not yet implemented
    this.aead = ['AESG'] // AES-GCM with a 12-byte tag and IV. S20P not yet implemented
    this.vers = ['Q039']
    this.cert = cert
  }

  setup (publicKey: Buffer, exp: number) {
    this.id = randomBytes(16).toString('hex')
    this.pubs = [publicKey] // 24-bit
    this.expy = exp
  }

  decodeTags () {
    const id = this.get(Tag.SCID)
    if (id == null || id.length !== 16) {
      throw QuicError.fromError(QuicError.QUIC_INVALID_CRYPTO_MESSAGE_TYPE)
    }
    this.id = id.toString('hex')

    const kexs = this.get(Tag.KEXS)
    if (kexs == null || kexs.length < 4) {
      throw QuicError.fromError(QuicError.QUIC_INVALID_CRYPTO_MESSAGE_TYPE)
    }
    this.kexs = [kexs.toString('utf8', 0, 4)]

    const aead = this.get(Tag.AEAD)
    if (aead == null || aead.length < 4) {
      throw QuicError.fromError(QuicError.QUIC_INVALID_CRYPTO_MESSAGE_TYPE)
    }
    this.aead = [aead.toString('utf8', 0, 4)]

    const vers = this.get(Tag.VER)
    if (vers == null || vers.length < 4) {
      throw QuicError.fromError(QuicError.QUIC_INVALID_CRYPTO_MESSAGE_TYPE)
    }
    this.vers = [vers.toString('utf8', 0, 4)]

    const pubs = this.get(Tag.PUBS)
    if (pubs == null || pubs.length < 3) {
      throw QuicError.fromError(QuicError.QUIC_INVALID_CRYPTO_MESSAGE_TYPE)
    }
    this.pubs = [pubs.slice(0, 3)]
  }

  encodeTags () {
    return
  }

  byteLen (): number {
    this.encodeTags()
    return super.byteLen()
  }

  writeTo (bufv: BufferVisitor): BufferVisitor {
    this.encodeTags()
    return super.writeTo(bufv)
  }
}

export class HandShake extends EventEmitter {
  state: number
  completed: boolean
  [kSession]: SessionRef
  constructor (session: SessionRef) {
    super()

    this.state = 0
    this.completed = false
    this[kSession] = session
  }

  handlePacket (_packet: RegularPacket, _rcvTime: number, _bufv: BufferVisitor) {
    throw new Error('Not implemented!')
  }
}

export class ClientHandShake extends HandShake {
  chlo: QuicTags
  initStream: Stream
  constructor (session: SessionRef) {
    super(session)
    this.chlo = new QuicTags(Tag.CHLO)
    this.initStream = session.request() // should be stream 1
  }

  handlePacket (_packet: RegularPacket, _rcvTime: number, _bufv: BufferVisitor) {
    return
  }

  setup () {
    this.emit('secureConnection')
    return
  }

  sendInchoateCHLO () {
    return
  }

  sendCHLO () {
    return
  }
}

export class ServerHandShake extends HandShake {
  scfg: ServerConfig
  sourceToken: SourceToken
  sentSHLO: boolean
  tagSNI: string
  tagXLCT: Buffer | null
  tagSCID: string

  constructor (session: SessionRef, sourceToken: SourceToken, scfg: ServerConfig) {
    super(session)
    this.scfg = scfg
    this.sourceToken = sourceToken
    this.sentSHLO = false
    this.tagSNI = ''
    this.tagXLCT = null
    this.tagSCID = ''
  }

  handlePacket (packet: RegularPacket, _rcvTime: number, bufv: BufferVisitor) {
    if (bufv.length < MinInitialPacketSize) {
      throw new QuicError('QUIC_HANDSHAKE_FAILED')
    }
    bufv.walk(ivLen)
    // const iv = bufv.buf.slice(bufv.start, bufv.end)
    const stream = StreamFrame.fromBuffer(bufv)
    if (stream.streamID.valueOf() !== 1 || stream.data == null) {
      throw QuicError.fromError(QuicError.QUIC_INVALID_CRYPTO_MESSAGE_TYPE)
    }
    packet.addFrames(stream)
    const tags = QuicTags.fromBuffer(new BufferVisitor(stream.data as Buffer))

    if (tags.name !== Tag.CHLO) {
      throw QuicError.fromError(QuicError.QUIC_INVALID_CRYPTO_MESSAGE_TYPE)
    }

    if (tags.has(Tag.FHL2)) {
      throw new QuicError('FHL2 experiment. Unsupported')
    }

    if (tags.has(Tag.NSTP)) {
      throw new QuicError('NSTP experiment. Unsupported')
    }

    // -------inchoate client hello messages-----
    const pdmd = tags.get(Tag.PDMD)
    if (pdmd == null || pdmd.toString() !== 'X509') {
      throw QuicError.fromError(QuicError.QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER)
    }

    const ver = tags.get(Tag.VER)
    if (ver == null || ver.toString() !== this[kSession][kVersion]) {
      throw QuicError.fromError(QuicError.QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER)
    }

    const xlct = tags.get(Tag.XLCT) // 64-bit
    if (xlct == null || xlct.length !== 8) {
      throw QuicError.fromError(QuicError.QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER)
    }
    this.tagXLCT = xlct

    const sni = tags.get(Tag.SNI)
    if (sni != null) { // optional
      this.tagSNI = sni.toString()
      if (this.tagSNI === '' || isIP(this.tagSNI) !== 0) {
        throw QuicError.fromError(QuicError.QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER)
      }
    }

    // const stk = tags.get(Tag.STK) // optional
    // const ccs = tags.get(Tag.CCS) // optional
    // const ccrt = tags.get(Tag.CCRT) // optional

    // -------full client hello messages-----
    const scid = tags.get(Tag.SCID)
    if (scid != null && scid.length === 16) {
      this.tagSCID = scid.toString('hex')
    }

    // if (this.isInchoateCHLO(tags, this.scfg.cert.raw)) {
    //   return this.sendREJ()
    // }
    // const ccrt = tags.get(Tag.AEAD)
    // const ccrt = tags.get(Tag.KEXS)
    // const ccrt = tags.get(Tag.NONC)
    // const ccrt = tags.get(Tag.PUBS)
    // const ccrt = tags.get(Tag.SNO) // optional
    // const ccrt = tags.get(Tag.CETV) // optional
  }

  isInchoateCHLO (tags: QuicTags, cert: Buffer): boolean {
    if (!tags.has(Tag.PUBS)) {
      return true
    }
    if (this.tagSCID === '' || this.tagSCID !== this.scfg.id) {
      return true
    }
    if (this.tagXLCT == null || !fnv1a64Hash(cert).equals(this.tagXLCT)) {
      return true
    }

    return !this.acceptSTK(tags.get(Tag.STK))
  }

  acceptSTK (buf: Buffer | null): boolean {
    if (buf == null) {
      return false
    }
    const stk = this.sourceToken.decode(buf)
    return stk != null
  }

  sendREJ () {
    return
  }

  sendSHLO () {
    return
  }
}
