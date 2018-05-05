'use strict'
// **Github:** https://github.com/fidm/quic
//
// **License:** MIT

import { promisify } from 'util'
import { lookup as dnsLookup } from 'dns'

export const lookup = promisify(dnsLookup)

export class Visitor {
  start: number
  end: number
  constructor (start: number = 0, end: number = 0) {
    this.start = start
    this.end = end > start ? end : start
  }

  reset (start: number = 0, end: number = 0): this {
    this.start = start
    if (end >= this.start) {
      this.end = end
    } else if (this.end < this.start) {
      this.end = this.start
    }
    return this
  }

  walk (steps: number): this {
    this.start = this.end
    this.end += steps
    return this
  }
}

export class BufferVisitor extends Visitor {
  buf: Buffer
  constructor (buf: Buffer, start: number = 0, end: number = 0) {
    super(start, end)
    this.buf = buf
  }

  get length () {
    return this.buf.length
  }

  isOutside (): boolean {
    return this.end > this.buf.length
  }
}

export interface ToBuffer {
  byteLen (): number
  writeTo (bufv: BufferVisitor): BufferVisitor
}

export function toBuffer (obj: ToBuffer): Buffer {
  const bufv = obj.writeTo(new BufferVisitor(Buffer.alloc(obj.byteLen())))
  return bufv.buf
}

// We define an unsigned 16-bit floating point value, inspired by IEEE floats
// (http://en.wikipedia.org/wiki/Half_precision_floating-point_format),
// with 5-bit exponent (bias 1), 11-bit mantissa (effective 12 with hidden
// bit) and denormals, but without signs, transfinites or fractions. Wire format
// 16 bits (little-endian byte order) are split into exponent (high 5) and
// mantissa (low 11)
// https://github.com/google/proto-quic/blob/master/src/net/quic/core/quic_protocol.h#L197
const Float16ExponentBits = 5
const Float16MantissaBits = 16 - Float16ExponentBits             // 11
const Float16MantissaEffectiveBits = Float16MantissaBits + 1     // 12
const Float16MantissaEffectiveValue = 1 << Float16MantissaEffectiveBits
// Float16MaxValue === readUFloat16(<Buffer 0xff 0xff>)
export const Float16MaxValue = 0x3FFC0000000

export function readUFloat16 (buf: Buffer, offset: number = 0): number {
  let value = buf.readUInt16BE(offset)
  if (value < Float16MantissaEffectiveValue) {
    return value
  }
  let exponent = value >> Float16MantissaBits
  --exponent
  value -= exponent << Float16MantissaBits
  // we can only use binary bitwise operators in 32 bits
  const res = value * Math.pow(2, exponent)
  return res < Float16MaxValue ? res : Float16MaxValue
}

export function writeUFloat16 (buf: Buffer, value: number, offset: number): Buffer {
  let res = 0
  if (value < Float16MantissaEffectiveValue) {
    res = value
  } else if (value >= Float16MaxValue) {
    res = 0xffff
  } else {
    let exponent = 0
    for (let i = 16; i >= 1; i /= 2) {
      if (value >= (1 << (Float16MantissaBits + i))) {
        exponent += i
        value /= Math.pow(2, i)
      }
    }
    res = Math.floor(value) + (exponent << Float16MantissaBits)
  }
  buf.writeUInt16BE(res, offset)
  return buf
}

const unsafeUIntRadix = 0xffffffffffff + 1
export function readUnsafeUInt (buf: Buffer, offset: number, len: number): number {
  let val = 0
  if (len > 6) {
    val = buf.readUIntBE(offset + len - 6, 6)
    const high = buf.readUIntBE(offset, len - 6)
    if (high > 0) {
      val += high * unsafeUIntRadix
    }
  } else if (len > 0) {
    val = buf.readUIntBE(offset, len)
  }
  return val
}

export function writeUnsafeUInt (buf: Buffer, val: number, offset: number, len: number): Buffer {
  if (len > 6) {
    if (val <= 0xffffffffffff) {
      buf.writeUIntBE(val, offset + len - 6, 6)
      buf.writeUIntBE(0, offset, len - 6) // clear cached bits
    } else {
      const high = Math.floor(val / unsafeUIntRadix)
      buf.writeUIntBE(val - high * unsafeUIntRadix, offset + len - 6, 6)
      buf.writeUIntBE(high, offset, len - 6)
    }
  } else if (len > 0) {
    buf.writeUIntBE(val, offset, len)
  }
  return buf
}

export class Queue<T> {

  private tail: T[]
  private head: T[]
  private offset: number
  private hLength: number
  constructor () {
    this.tail = []
    this.head = []
    this.offset = 0
    this.hLength = 0
  }

  get length (): number {
    return this.hLength + this.tail.length - this.offset
  }

  first (): T | undefined {
    return this.hLength === this.offset ? this.tail[0] : this.head[this.offset]
  }

  push (item: T): void {
    this.tail.push(item)
  }

  pop (): T | undefined {
    if (this.tail.length > 0) {
      return this.tail.pop()
    }
    if (this.hLength === 0) {
      return
    }
    this.hLength--
    return this.head.pop()
  }

  unshift (item: T): void {
    if (this.offset === 0) {
      this.hLength++
      this.head.unshift(item)
    } else {
      this.offset--
      this.head[this.offset] = item
    }
  }

  shift (): T | undefined {
    if (this.offset === this.hLength) {
      if (this.tail.length === 0) {
        return
      }

      const tmp = this.head
      tmp.length = 0
      this.head = this.tail
      this.tail = tmp
      this.offset = 0
      this.hLength = this.head.length
    }
    return this.head[this.offset++]
  }

  toArray (): T[] {
    const arr: T[] = []
    if (this.offset === this.hLength) {
      for (const item of this.tail) {
        arr.push(item)
      }
    } else {
      for (let i = this.offset, l = this.head.length; i < l; i++) {
        arr.push(this.head[i])
      }
    }
    return arr
  }

  reset (): void {
    this.offset = 0
    this.hLength = 0
    this.tail.length = 0
    this.head.length = 0
  }

  migrateTo (queue: Queue<T>): Queue<T> {
    let i = this.offset
    const len = this.tail.length
    while (i < this.hLength) {
      queue.push(this.head[i++])
    }

    i = 0
    while (i < len) {
      queue.push(this.tail[i++])
    }
    this.offset = this.hLength = this.head.length = this.tail.length = 0
    return queue
  }
}
