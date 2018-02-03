'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const errors = Object.create(null)
const streamErrors = Object.create(null)
const INVALID_ERROR = {name: 'INVALID_ERROR_CODE', code: 0xffffffff}
const INVALID_RST_STREAM_ERROR = {name: 'INVALID_RST_STREAM_ERROR_CODE', code: 0xffffffff}

// https://github.com/google/proto-quic/blob/master/src/net/quic/core/quic_error_codes.h
/** QuicError representing a QUIC Error. */
class QuicError extends Error {
  constructor (nameOrCode) {
    let error = errors[nameOrCode] || INVALID_ERROR
    super(error !== INVALID_ERROR ? error.message : nameOrCode)
    this.name = error.name
    this.code = error.code
    Error.captureStackTrace(this, QuicError)
  }

  toBuffer () {
    let buf = Buffer.alloc(4)
    buf.writeUInt32LE(this.code)
    return buf
  }

  static fromBuffer (buf) {
    let code = buf.readUInt32LE(0, true)
    return code ? new QuicError(code) : null
  }
}

/** QuicError representing a QUIC Stream Error. */
class QuicStreamError extends Error {
  constructor (nameOrCode) {
    let error = streamErrors[nameOrCode] || INVALID_RST_STREAM_ERROR
    super(error !== INVALID_RST_STREAM_ERROR ? error.message : nameOrCode)
    this.name = error.name
    this.code = error.code
    Error.captureStackTrace(this, QuicStreamError)
  }

  toBuffer () {
    let buf = Buffer.alloc(4)
    buf.writeUInt32LE(this.code)
    return buf
  }

  static fromBuffer (buf) {
    let code = buf.readUInt32LE(0, true)
    return code ? new QuicStreamError(code) : null
  }
}

streamErrors.QUIC_STREAM_NO_ERROR = {
  code: 0,
  message: ''
}

streamErrors.QUIC_ERROR_PROCESSING_STREAM = {
  code: 1,
  message: 'There was some error which halted stream processing.'
}

streamErrors.QUIC_MULTIPLE_TERMINATION_OFFSETS = {
  code: 2,
  message: 'We got two fin or reset offsets which did not match.'
}

streamErrors.QUIC_BAD_APPLICATION_PAYLOAD = {
  code: 3,
  message: 'We got bad payload and can not respond to it at the protocol level.'
}

streamErrors.QUIC_STREAM_CONNECTION_ERROR = {
  code: 4,
  message: 'Stream closed due to connection error. No reset frame is sent when this happens.'
}

streamErrors.QUIC_STREAM_PEER_GOING_AWAY = {
  code: 5,
  message: 'GoAway frame sent. No more stream can be created.'
}

streamErrors.QUIC_STREAM_CANCELLED = {
  code: 6,
  message: 'The stream has been cancelled.'
}

streamErrors.QUIC_RST_ACKNOWLEDGEMENT = {
  code: 7,
  message: 'Closing stream locally, sending a RST to allow for proper flow control accounting. Sent in response to a RST from the peer.'
}

streamErrors.QUIC_REFUSED_STREAM = {
  code: 8,
  message: 'Receiver refused to create the stream (because its limit on open streams has been reached). The sender should retry the request later (using another stream).'
}

streamErrors.QUIC_INVALID_PROMISE_URL = {
  code: 9,
  message: 'Invalid URL in PUSH_PROMISE request header.'
}

streamErrors.QUIC_UNAUTHORIZED_PROMISE_URL = {
  code: 10,
  message: 'Server is not authoritative for this URL.'
}

streamErrors.QUIC_DUPLICATE_PROMISE_URL = {
  code: 11,
  message: 'Can\'t have more than one active PUSH_PROMISE per URL.'
}

streamErrors.QUIC_PROMISE_VARY_MISMATCH = {
  code: 12,
  message: 'Vary check failed.'
}

streamErrors.QUIC_INVALID_PROMISE_METHOD = {
  code: 13,
  message: 'Only GET and HEAD methods allowed.'
}

streamErrors.QUIC_PUSH_STREAM_TIMED_OUT = {
  code: 14,
  message: 'The push stream is unclaimed and timed out.'
}

streamErrors.QUIC_HEADERS_TOO_LARGE = {
  code: 15,
  message: 'Received headers were too large.'
}

streamErrors.QUIC_STREAM_LAST_ERROR = {
  code: 16,
  // No error. Used as bound while iterating.
  message: 'No error'
}

for (let key of Object.keys(streamErrors)) {
  let error = streamErrors[key]
  error.name = key
  streamErrors[error.code] = error
}

errors.QUIC_NO_ERROR = {
  code: 0,
  message: ''
}

errors.QUIC_INTERNAL_ERROR = {
  code: 1,
  message: 'Connection has reached an invalid state.'
}

errors.QUIC_STREAM_DATA_AFTER_TERMINATION = {
  code: 2,
  message: 'There were data frames after the a fin or reset.'
}

errors.QUIC_INVALID_PACKET_HEADER = {
  code: 3,
  message: 'Control frame is malformed.'
}

errors.QUIC_INVALID_FRAME_DATA = {
  code: 4,
  message: 'Frame data is malformed.'
}

errors.QUIC_MISSING_PAYLOAD = {
  code: 48,
  message: 'The packet contained no payload.'
}

errors.QUIC_INVALID_FEC_DATA = {
  code: 5,
  message: 'FEC data is malformed.'
}

errors.QUIC_INVALID_STREAM_DATA = {
  code: 46,
  message: 'STREAM frame data is malformed.'
}

errors.QUIC_OVERLAPPING_STREAM_DATA = {
  code: 87,
  message: 'STREAM frame data overlaps with buffered data.'
}

errors.QUIC_UNENCRYPTED_STREAM_DATA = {
  code: 61,
  message: 'Received STREAM frame data is not encrypted.'
}

errors.QUIC_ATTEMPT_TO_SEND_UNENCRYPTED_STREAM_DATA = {
  code: 88,
  message: 'Attempt to send unencrypted STREAM frame.'
}

errors.QUIC_MAYBE_CORRUPTED_MEMORY = {
  code: 89,
  message: 'Received a frame which is likely the result of memory corruption.'
}

errors.QUIC_UNENCRYPTED_FEC_DATA = {
  code: 77,
  message: 'FEC frame data is not encrypted.'
}

errors.QUIC_INVALID_RST_STREAM_DATA = {
  code: 6,
  message: 'RST_STREAM frame data is malformed.'
}

errors.QUIC_INVALID_CONNECTION_CLOSE_DATA = {
  code: 7,
  message: 'CONNECTION_CLOSE frame data is malformed.'
}

errors.QUIC_INVALID_GOAWAY_DATA = {
  code: 8,
  message: 'GOAWAY frame data is malformed.'
}

errors.QUIC_INVALID_WINDOW_UPDATE_DATA = {
  code: 57,
  message: 'WINDOW_UPDATE frame data is malformed.'
}

errors.QUIC_INVALID_BLOCKED_DATA = {
  code: 58,
  message: 'BLOCKED frame data is malformed.'
}

errors.QUIC_INVALID_STOP_WAITING_DATA = {
  code: 60,
  message: 'STOP_WAITING frame data is malformed.'
}

errors.QUIC_INVALID_PATH_CLOSE_DATA = {
  code: 78,
  message: 'PATH_CLOSE frame data is malformed.'
}

errors.QUIC_INVALID_ACK_DATA = {
  code: 9,
  message: 'ACK frame data is malformed.'
}

errors.QUIC_INVALID_VERSION_NEGOTIATION_PACKET = {
  code: 10,
  message: 'Version negotiation packet is malformed.'
}

errors.QUIC_INVALID_PUBLIC_RST_PACKET = {
  code: 11,
  message: 'Public RST packet is malformed.'
}

errors.QUIC_DECRYPTION_FAILURE = {
  code: 12,
  message: 'There was an error decrypting.'
}

errors.QUIC_ENCRYPTION_FAILURE = {
  code: 13,
  message: 'There was an error encrypting.'
}

errors.QUIC_PACKET_TOO_LARGE = {
  code: 14,
  message: 'The packet exceeded kMaxPacketSize.'
}

errors.QUIC_PEER_GOING_AWAY = {
  code: 16,
  message: 'The peer is going away.  May be a client or server.'
}

errors.QUIC_INVALID_STREAM_ID = {
  code: 17,
  message: 'A stream ID was invalid.'
}

errors.QUIC_INVALID_PRIORITY = {
  code: 49,
  message: 'A priority was invalid.'
}

errors.QUIC_TOO_MANY_OPEN_STREAMS = {
  code: 18,
  message: 'Too many streams already open.'
}

errors.QUIC_TOO_MANY_AVAILABLE_STREAMS = {
  code: 76,
  message: 'The peer created too many available streams.'
}

errors.QUIC_PUBLIC_RESET = {
  code: 19,
  message: 'Received public reset for this connection.'
}

errors.QUIC_INVALID_VERSION = {
  code: 20,
  message: 'Invalid protocol version.'
}

errors.QUIC_INVALID_HEADER_ID = {
  code: 22,
  message: 'The Header ID for a stream was too far from the previous.'
}

errors.QUIC_INVALID_NEGOTIATED_VALUE = {
  code: 23,
  message: 'Negotiable parameter received during handshake had invalid value.'
}

errors.QUIC_DECOMPRESSION_FAILURE = {
  code: 24,
  message: 'There was an error decompressing data.'
}

errors.QUIC_NETWORK_IDLE_TIMEOUT = {
  code: 25,
  message: 'The connection timed out due to no network activity.'
}

errors.QUIC_HANDSHAKE_TIMEOUT = {
  code: 67,
  message: 'The connection timed out waiting for the handshake to complete.'
}

errors.QUIC_ERROR_MIGRATING_ADDRESS = {
  code: 26,
  message: 'There was an error encountered migrating addresses.'
}

errors.QUIC_ERROR_MIGRATING_PORT = {
  code: 86,
  message: 'There was an error encountered migrating port only.'
}

errors.QUIC_PACKET_WRITE_ERROR = {
  code: 27,
  message: 'There was an error while writing to the socket.'
}

errors.QUIC_PACKET_READ_ERROR = {
  code: 51,
  message: 'There was an error while reading from the socket.'
}

errors.QUIC_EMPTY_STREAM_FRAME_NO_FIN = {
  code: 50,
  message: 'We received a STREAM_FRAME with no data and no fin flag set.'
}

errors.QUIC_INVALID_HEADERS_STREAM_DATA = {
  code: 56,
  message: 'We received invalid data on the headers stream.'
}

errors.QUIC_HEADERS_STREAM_DATA_DECOMPRESS_FAILURE = {
  code: 97,
  message: 'Invalid data on the headers stream received because of decompression failure.'
}

errors.QUIC_FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA = {
  code: 59,
  message: 'The peer received too much data, violating flow control.'
}

errors.QUIC_FLOW_CONTROL_SENT_TOO_MUCH_DATA = {
  code: 63,
  message: 'The peer sent too much data, violating flow control.'
}

errors.QUIC_FLOW_CONTROL_INVALID_WINDOW = {
  code: 64,
  message: 'The peer received an invalid flow control window.'
}

errors.QUIC_CONNECTION_IP_POOLED = {
  code: 62,
  message: 'The connection has been IP pooled into an existing connection.'
}

errors.QUIC_TOO_MANY_OUTSTANDING_SENT_PACKETS = {
  code: 68,
  message: 'The connection has too many outstanding sent packets.'
}

errors.QUIC_TOO_MANY_OUTSTANDING_RECEIVED_PACKETS = {
  code: 69,
  message: 'The connection has too many outstanding received packets.'
}

errors.QUIC_CONNECTION_CANCELLED = {
  code: 70,
  message: 'The quic connection has been cancelled.'
}

errors.QUIC_BAD_PACKET_LOSS_RATE = {
  code: 71,
  message: 'Disabled QUIC because of high packet loss rate.'
}

errors.QUIC_PUBLIC_RESETS_POST_HANDSHAKE = {
  code: 73,
  message: 'Disabled QUIC because of too many PUBLIC_RESETs post handshake.'
}

errors.QUIC_FAILED_TO_SERIALIZE_PACKET = {
  code: 75,
  message: 'Closed because we failed to serialize a packet.'
}

errors.QUIC_TOO_MANY_RTOS = {
  code: 85,
  message: 'QUIC timed out after too many RTOs.'
}

// Crypto errors.

errors.QUIC_HANDSHAKE_FAILED = {
  code: 28,
  message: 'Hanshake failed.'
}

errors.QUIC_CRYPTO_TAGS_OUT_OF_ORDER = {
  code: 29,
  message: 'Handshake message contained out of order tags.'
}

errors.QUIC_CRYPTO_TOO_MANY_ENTRIES = {
  code: 30,
  message: 'Handshake message contained too many entries.'
}

errors.QUIC_CRYPTO_INVALID_VALUE_LENGTH = {
  code: 31,
  message: 'Handshake message contained an invalid value length.'
}

errors.QUIC_CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE = {
  code: 32,
  message: 'A crypto message was received after the handshake was complete.'
}

errors.QUIC_INVALID_CRYPTO_MESSAGE_TYPE = {
  code: 33,
  message: 'A crypto message was received with an illegal message tag.'
}

errors.QUIC_INVALID_CRYPTO_MESSAGE_PARAMETER = {
  code: 34,
  message: 'A crypto message was received with an illegal parameter.'
}

errors.QUIC_INVALID_CHANNEL_ID_SIGNATURE = {
  code: 52,
  message: 'An invalid channel id signature was supplied.'
}

errors.QUIC_CRYPTO_MESSAGE_PARAMETER_NOT_FOUND = {
  code: 35,
  message: 'A crypto message was received with a mandatory parameter missing.'
}

errors.QUIC_CRYPTO_MESSAGE_PARAMETER_NO_OVERLAP = {
  code: 36,
  message: 'A crypto message was received with a parameter that has no overlap with the local parameter.'
}

errors.QUIC_CRYPTO_MESSAGE_INDEX_NOT_FOUND = {
  code: 37,
  message: 'A crypto message was received that contained a parameter with too few values.'
}

errors.QUIC_UNSUPPORTED_PROOF_DEMAND = {
  code: 94,
  message: 'A demand for an unsupport proof type was received.'
}

errors.QUIC_CRYPTO_INTERNAL_ERROR = {
  code: 38,
  message: 'An internal error occured in crypto processing.'
}

errors.QUIC_CRYPTO_VERSION_NOT_SUPPORTED = {
  code: 39,
  message: 'A crypto handshake message specified an unsupported version.'
}

errors.QUIC_CRYPTO_HANDSHAKE_STATELESS_REJECT = {
  code: 72,
  message: 'A crypto handshake message resulted in a stateless reject.'
}

errors.QUIC_CRYPTO_NO_SUPPORT = {
  code: 40,
  message: 'There was no intersection between the crypto primitives supported by the peer and ourselves.'
}

errors.QUIC_CRYPTO_TOO_MANY_REJECTS = {
  code: 41,
  message: 'The server rejected our client hello messages too many times.'
}

errors.QUIC_PROOF_INVALID = {
  code: 42,
  message: 'The client rejected the server\'s certificate chain or signature.'
}

errors.QUIC_CRYPTO_DUPLICATE_TAG = {
  code: 43,
  message: 'A crypto message was received with a duplicate tag.'
}

errors.QUIC_CRYPTO_ENCRYPTION_LEVEL_INCORRECT = {
  code: 44,
  // i.e. it should have been encrypted but was not.
  message: 'A crypto message was received with the wrong encryption level'
}

errors.QUIC_CRYPTO_SERVER_CONFIG_EXPIRED = {
  code: 45,
  message: 'The server config for a server has expired.'
}

errors.QUIC_CRYPTO_SYMMETRIC_KEY_SETUP_FAILED = {
  code: 53,
  message: 'We failed to setup the symmetric keys for a connection.'
}

errors.QUIC_CRYPTO_MESSAGE_WHILE_VALIDATING_CLIENT_HELLO = {
  code: 54,
  message: 'A handshake message arrived, but we are still validating the previous handshake message.'
}

errors.QUIC_CRYPTO_UPDATE_BEFORE_HANDSHAKE_COMPLETE = {
  code: 65,
  message: 'A server config update arrived before the handshake is complete.'
}

errors.QUIC_CRYPTO_CHLO_TOO_LARGE = {
  code: 90,
  message: 'CHLO cannot fit in one packet.'
}

errors.QUIC_VERSION_NEGOTIATION_MISMATCH = {
  code: 55,
  message: 'This connection involved a version negotiation which appears to have been tampered with.'
}

// Multipath errors.

errors.QUIC_BAD_MULTIPATH_FLAG = {
  code: 79,
  message: 'Multipath is not enabled, but a packet with multipath flag on is received.'
}

errors.QUIC_MULTIPATH_PATH_DOES_NOT_EXIST = {
  code: 91,
  message: 'A path is supposed to exist but does not.'
}

errors.QUIC_MULTIPATH_PATH_NOT_ACTIVE = {
  code: 92,
  message: 'A path is supposed to be active but is not.'
}

errors.QUIC_IP_ADDRESS_CHANGED = {
  code: 80,
  message: 'IP address changed causing connection close.'
}

// Connection migration errors.

errors.QUIC_CONNECTION_MIGRATION_NO_MIGRATABLE_STREAMS = {
  code: 81,
  message: 'Network changed, but connection had no migratable streams.'
}

errors.QUIC_CONNECTION_MIGRATION_TOO_MANY_CHANGES = {
  code: 82,
  message: 'Connection changed networks too many times.'
}

errors.QUIC_CONNECTION_MIGRATION_NO_NEW_NETWORK = {
  code: 83,
  message: 'Connection migration was attempted, but there was no new network to migrate to.'
}

errors.QUIC_CONNECTION_MIGRATION_NON_MIGRATABLE_STREAM = {
  code: 84,
  message: 'Network changed, but connection had one or more non-migratable streams.'
}

errors.QUIC_TOO_MANY_FRAME_GAPS = {
  code: 93,
  message: 'Stream frames arrived too discontiguously so that stream sequencer buffer maintains too many gaps.'
}

errors.QUIC_STREAM_SEQUENCER_INVALID_STATE = {
  code: 95,
  message: 'Sequencer buffer get into weird state where continuing read/write will lead to crash.'
}

errors.QUIC_TOO_MANY_SESSIONS_ON_SERVER = {
  code: 96,
  message: 'Connection closed because of server hits max number of sessions allowed.'
}

errors.QUIC_LAST_ERROR = {
  code: 98,
  // No error. Used as bound while iterating.
  message: 'No error'
}

for (let key of Object.keys(errors)) {
  let error = errors[key]
  error.name = key
  errors[error.code] = error
}

exports.QuicError = QuicError
exports.QuicStreamError = QuicStreamError
