'use strict'
// **Github:** https://github.com/fidm/quic
//
// **License:** MIT

// https://docs.google.com/document/d/1F2YfdDXKpy20WVKJueEf4abn_LVZHhMUMS5gX6Pgjl4/edit#

export  class FlowController {
  maxSendOffset: number
  maxReceiveOffset: number
  maxReceiveWindowSize: number
  maxReceiveWindowSizeLimit: number
  writtenOffset: number
  consumedOffset: number
  highestReceivedOffset: number
  lastWindowUpdateAt: number
  constructor (windowSize: number, windowSizeLimit: number) {
    // Both stream and session windows start with a default value of 16 KB
    this.maxSendOffset = 16 * 1024
    this.maxReceiveOffset = 16 * 1024
    this.maxReceiveWindowSize = windowSize
    this.maxReceiveWindowSizeLimit = windowSizeLimit
    this.writtenOffset = 0
    this.consumedOffset = 0
    this.highestReceivedOffset = 0
    this.lastWindowUpdateAt = 0
  }

  updateMaxSendOffset (byteOffset: number): boolean {
    if (byteOffset > this.maxSendOffset) {
      this.maxSendOffset = byteOffset
      return true
    }
    return false
  }

  shouldUpdateWindow (): boolean {
    return (this.maxReceiveOffset - this.consumedOffset) < (this.maxReceiveWindowSize / 2)
  }

  updateWindowOffset (rtt: number): number {
    const time = Date.now()
    this._autoTuning(rtt, time)
    this.lastWindowUpdateAt = time
    this.maxReceiveOffset = this.consumedOffset + this.maxReceiveWindowSize
    return this.maxReceiveOffset
  }

  _autoTuning (rtt: number, now: number) {
    if (this.lastWindowUpdateAt > 0 && this.maxReceiveWindowSize < this.maxReceiveWindowSizeLimit &&
      (now - this.lastWindowUpdateAt <= rtt * 2)) {
      this.maxReceiveWindowSize =
        Math.min(this.maxReceiveWindowSize * 2, this.maxReceiveWindowSizeLimit)
    }
  }
}

export class ConnectionFlowController extends FlowController {
  lastBlockedAt: number // timestamp, ms
  lastBlockedStreamId: number // timestamp, ms
  constructor (windowSize: number, windowSizeLimit: number) {
    super(windowSize, windowSizeLimit)
    this.lastBlockedAt = 0
    this.lastBlockedStreamId = 0
  }

  updateBlockedFrame (streamId: number, rcvTime: number) {
    this.lastBlockedAt = rcvTime
    this.lastBlockedStreamId = streamId
  }
}

export class StreamFlowController extends FlowController {
  cfc: ConnectionFlowController
  constructor (windowSize: number, windowSizeLimit: number,  cfc: ConnectionFlowController) {
    super(windowSize, windowSizeLimit)
    this.cfc = cfc
  }

  updateWrittenOffset (byteLen: number) {
    this.writtenOffset += byteLen
    this.cfc.writtenOffset += byteLen
  }

  updateConsumedOffset (consumedOffset: number) {
    if (consumedOffset > this.consumedOffset) {
      this.cfc.consumedOffset -= this.consumedOffset
      this.consumedOffset = consumedOffset
      this.cfc.consumedOffset += consumedOffset
    }
  }

  updateHighestReceived (byteOffset: number) {
    if (byteOffset > this.highestReceivedOffset) {
      this.cfc.highestReceivedOffset -= this.highestReceivedOffset
      this.highestReceivedOffset = byteOffset
      this.cfc.highestReceivedOffset += byteOffset
    }
  }

  isBlocked (): boolean {
    return this.highestReceivedOffset > this.maxReceiveOffset
  }

  willBlocked (byteLen: number): boolean {
    return byteLen > 0 && (this.maxSendOffset - this.writtenOffset < byteLen)
  }
}
