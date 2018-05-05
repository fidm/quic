'use strict'
// **Github:** https://github.com/fidm/quic
//
// **License:** MIT

export const kID = Symbol('id')
export const kVal = Symbol('Protocol.val')
export const kSession = Symbol('session')
export const kStreams = Symbol('streams')
export const kTimers = Symbol('timers')
export const kSocket = Symbol('socket')
export const kState = Symbol('state')
export const kType = Symbol('type')
export const kVersion = Symbol('version')
export const kServer = Symbol('server')
export const kConns = Symbol('conns')
export const kClientState = Symbol('clientState')
export const kNextStreamID = Symbol('nextStreamID')
export const kNextPacketNumber = Symbol('nextPacketNumber')
export const kACKHandler = Symbol('ACKHandler')
export const kIntervalCheck = Symbol('intervalCheck')
export const kDelayAckTimer = Symbol('delayAckTimer')
export const kUnackedPackets = Symbol('unackedPackets')
export const kFC = Symbol('flowController')
export const kHS = Symbol('handShake')
export const kRTT = Symbol('RTTStats')
