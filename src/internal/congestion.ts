'use strict'
// **Github:** https://github.com/fidm/quic
//
// **License:** MIT

const initialRTTus = 1000 // microsecond
const rttAlpha = 0.25
const oneMinusAlpha = 1 - rttAlpha

export class RTTStats {
  minRTT: number
  latestRTT: number
  smoothedRTT: number
  constructor () {
    this.minRTT = 0
    this.latestRTT = initialRTTus
    this.smoothedRTT = initialRTTus
  }

  get msRTT () {
    return Math.floor(this.smoothedRTT / 1000)
  }

  // TODO: it is a simple version
  updateRTT (sentTime: number, rcvTime: number, ackDelay: number) {
    if (sentTime <= 0 || rcvTime <= sentTime) {
      return
    }

    const sendDelta = (rcvTime - sentTime) * 1000 - ackDelay
    if (sendDelta <= 0) {
      return
    }

    let sample = sendDelta
    if (sample > 2 * this.latestRTT) {
      sample = Math.ceil(0.618 * sample)
    }

    this.latestRTT = sample
    if (this.minRTT > sample || this.minRTT === 0) {
      this.minRTT = sample
    }
    this.smoothedRTT = Math.ceil(this.smoothedRTT * oneMinusAlpha + sample * rttAlpha)
  }
}
