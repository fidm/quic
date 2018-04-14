'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

import { promisify } from 'util'
import { lookup as dnsLookup } from 'dns'

export const lookup = promisify(dnsLookup)

// BufferVisitor is a buffer wrapped by Visitor
export interface BufferVisitor extends Buffer {
  v: Visitor
}

/** Visitor representing a Buffer visitor. */
export class Visitor {
  static wrap (buf: Buffer): BufferVisitor {
    Object.assign(buf, { v: new Visitor() })
    return buf as BufferVisitor
  }

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

export interface ToBuffer {
  byteLen (): number
  writeTo (bufv: BufferVisitor): BufferVisitor
}

export function toBuffer (obj: ToBuffer): BufferVisitor {
  const bufv = obj.writeTo(Visitor.wrap(Buffer.alloc(obj.byteLen())))
  bufv.v.reset(0, 0)
  return bufv
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
  let value = buf.readUInt16LE(offset)
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
  buf.writeUInt16LE(res, offset)
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
