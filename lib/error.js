'use strict'
// **Github:** https://github.com/toajs/quic
//
// **License:** MIT

const errors = module.exports = Object.create(null)
const UNKNOWN_ERROR = {name: 'UNKNOWN_ERROR', code: 0xffffffff}

class QuicError extends Error {
  constructor (nameOrCode) {
    let error = errors[nameOrCode] || UNKNOWN_ERROR
    super(error !== UNKNOWN_ERROR ? error.message : nameOrCode)
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

errors.NO_ERROR = {
  code: 0,
  message: ''
}

errors.INTERNAL_ERROR = {
  code: 1,
  message: 'Connection has reached an invalid state.'
}

errors.STREAM_DATA_AFTER_TERMINATION = {
  code: 2,
  message: 'There were data frames after the a fin or reset.'
}
errors.INVALID_PACKET_HEADER = {
  code: 3,
  message: 'Control frame is malformed.'
}

errors.INVALID_FRAME_DATA = {
  code: 4,
  message: 'Frame data is malformed.'
}

errors.MISSING_PAYLOAD = {
  code: 48,
  message: 'The packet contained no payload.'
}

errors.INVALID_FEC_DATA = {
  code: 5,
  message: 'FEC data is malformed.'
}

errors.INVALID_STREAM_DATA = {
  code: 46,
  message: 'STREAM frame data is malformed.'
}

errors.OVERLAPPING_STREAM_DATA = {
  code: 87,
  message: 'STREAM frame data overlaps with buffered data.'
}

errors.UNENCRYPTED_STREAM_DATA = {
  code: 61,
  message: 'Received STREAM frame data is not encrypted.'
}

errors.ATTEMPT_TO_SEND_UNENCRYPTED_STREAM_DATA = {
  code: 88,
  message: 'Attempt to send unencrypted STREAM frame.'
}

errors.MAYBE_CORRUPTED_MEMORY = {
  code: 89,
  message: 'Received a frame which is likely the result of memory corruption.'
}

errors.UNENCRYPTED_FEC_DATA = {
  code: 77,
  message: 'FEC frame data is not encrypted.'
}

errors.INVALID_RST_STREAM_DATA = {
  code: 6,
  message: 'RST_STREAM frame data is malformed.'
}

errors.INVALID_CONNECTION_CLOSE_DATA = {
  code: 7,
  message: 'CONNECTION_CLOSE frame data is malformed.'
}

errors.INVALID_GOAWAY_DATA = {
  code: 8,
  message: 'GOAWAY frame data is malformed.'
}

errors.INVALID_WINDOW_UPDATE_DATA = {
  code: 57,
  message: 'WINDOW_UPDATE frame data is malformed.'
}

errors.INVALID_BLOCKED_DATA = {
  code: 58,
  message: 'BLOCKED frame data is malformed.'
}

errors.INVALID_STOP_WAITING_DATA = {
  code: 60,
  message: 'STOP_WAITING frame data is malformed.'
}

errors.INVALID_PATH_CLOSE_DATA = {
  code: 78,
  message: 'PATH_CLOSE frame data is malformed.'
}

errors.INVALID_ACK_DATA = {
  code: 9,
  message: 'ACK frame data is malformed.'
}

errors.INVALID_VERSION_NEGOTIATION_PACKET = {
  code: 10,
  message: 'Version negotiation packet is malformed.'
}

errors.INVALID_PUBLIC_RST_PACKET = {
  code: 11,
  message: 'Public RST packet is malformed.'
}

errors.DECRYPTION_FAILURE = {
  code: 12,
  message: 'There was an error decrypting.'
}

errors.ENCRYPTION_FAILURE = {
  code: 13,
  message: 'There was an error encrypting.'
}

errors.PACKET_TOO_LARGE = {
  code: 14,
  message: 'The packet exceeded kMaxPacketSize.'
}

errors.PEER_GOING_AWAY = {
  code: 16,
  message: 'The peer is going away.  May be a client or server.'
}

errors.INVALID_STREAM_ID = {
  code: 17,
  message: 'A stream ID was invalid.'
}

errors.INVALID_PRIORITY = {
  code: 49,
  message: 'A priority was invalid.'
}

errors.TOO_MANY_OPEN_STREAMS = {
  code: 18,
  message: 'Too many streams already open.'
}

errors.TOO_MANY_AVAILABLE_STREAMS = {
  code: 76,
  message: 'The peer created too many available streams.'
}

errors.PUBLIC_RESET = {
  code: 19,
  message: 'Received public reset for this connection.'
}

errors.INVALID_VERSION = {
  code: 20,
  message: 'Invalid protocol version.'
}

errors.INVALID_HEADER_ID = {
  code: 22,
  message: 'The Header ID for a stream was too far from the previous.'
}

errors.INVALID_NEGOTIATED_VALUE = {
  code: 23,
  message: 'Negotiable parameter received during handshake had invalid value.'
}

errors.DECOMPRESSION_FAILURE = {
  code: 24,
  message: 'There was an error decompressing data.'
}

errors.NETWORK_IDLE_TIMEOUT = {
  code: 25,
  message: 'The connection timed out due to no network activity.'
}

errors.HANDSHAKE_TIMEOUT = {
  code: 67,
  message: 'The connection timed out waiting for the handshake to complete.'
}

errors.ERROR_MIGRATING_ADDRESS = {
  code: 26,
  message: 'There was an error encountered migrating addresses.'
}

errors.ERROR_MIGRATING_PORT = {
  code: 86,
  message: 'There was an error encountered migrating port only.'
}

errors.PACKET_WRITE_ERROR = {
  code: 27,
  message: 'There was an error while writing to the socket.'
}

errors.PACKET_READ_ERROR = {
  code: 51,
  message: 'There was an error while reading from the socket.'
}

errors.EMPTY_STREAM_FRAME_NO_FIN = {
  code: 50,
  message: 'We received a STREAM_FRAME with no data and no fin flag set.'
}

errors.INVALID_HEADERS_STREAM_DATA = {
  code: 56,
  message: 'We received invalid data on the headers stream.'
}

errors.FLOW_CONTROL_RECEIVED_TOO_MUCH_DATA = {
  code: 59,
  message: 'The peer received too much data, violating flow control.'
}

errors.FLOW_CONTROL_SENT_TOO_MUCH_DATA = {
  code: 63,
  message: 'The peer sent too much data, violating flow control.'
}

errors.FLOW_CONTROL_INVALID_WINDOW = {
  code: 64,
  message: 'The peer received an invalid flow control window.'
}

errors.CONNECTION_IP_POOLED = {
  code: 62,
  message: 'The connection has been IP pooled into an existing connection.'
}

errors.TOO_MANY_OUTSTANDING_SENT_PACKETS = {
  code: 68,
  message: 'The connection has too many outstanding sent packets.'
}

errors.TOO_MANY_OUTSTANDING_RECEIVED_PACKETS = {
  code: 69,
  message: 'The connection has too many outstanding received packets.'
}

errors.CONNECTION_CANCELLED = {
  code: 70,
  message: 'The quic connection has been cancelled.'
}

errors.BAD_PACKET_LOSS_RATE = {
  code: 71,
  message: 'Disabled QUIC because of high packet loss rate.'
}

errors.PUBLIC_RESETS_POST_HANDSHAKE = {
  code: 73,
  message: 'Disabled QUIC because of too many PUBLIC_RESETs post handshake.'
}

errors.TIMEOUTS_WITH_OPEN_STREAMS = {
  code: 74,
  message: 'Disabled QUIC because of too many timeouts with streams open.'
}

errors.FAILED_TO_SERIALIZE_PACKET = {
  code: 75,
  message: 'Closed because we failed to serialize a packet.'
}

errors.TOO_MANY_RTOS = {
  code: 85,
  message: 'QUIC timed out after too many RTOs.'
}

// Crypto errors.

errors.HANDSHAKE_FAILED = {
  code: 28,
  message: 'Hanshake failed.'
}

errors.CRYPTO_TAGS_OUT_OF_ORDER = {
  code: 29,
  message: 'Handshake message contained out of order tags.'
}

errors.CRYPTO_TOO_MANY_ENTRIES = {
  code: 30,
  message: 'Handshake message contained too many entries.'
}

errors.CRYPTO_INVALID_VALUE_LENGTH = {
  code: 31,
  message: 'Handshake message contained an invalid value length.'
}

errors.CRYPTO_MESSAGE_AFTER_HANDSHAKE_COMPLETE = {
  code: 32,
  message: 'A crypto message was received after the handshake was complete.'
}

errors.INVALID_CRYPTO_MESSAGE_TYPE = {
  code: 33,
  message: 'A crypto message was received with an illegal message tag.'
}

errors.INVALID_CRYPTO_MESSAGE_PARAMETER = {
  code: 34,
  message: 'A crypto message was received with an illegal parameter.'
}

errors.INVALID_CHANNEL_ID_SIGNATURE = {
  code: 52,
  message: 'An invalid channel id signature was supplied.'
}

errors.CRYPTO_MESSAGE_PARAMETER_NOT_FOUND = {
  code: 35,
  message: 'A crypto message was received with a mandatory parameter missing.'
}

errors.CRYPTO_MESSAGE_PARAMETER_NO_OVERLAP = {
  code: 36,
  message: 'A crypto message was received with a parameter that has no overlap with the local parameter.'
}

errors.CRYPTO_MESSAGE_INDEX_NOT_FOUND = {
  code: 37,
  message: 'A crypto message was received that contained a parameter with too few values.'
}

errors.CRYPTO_INTERNAL_ERROR = {
  code: 38,
  message: 'An internal error occured in crypto processing.'
}

errors.CRYPTO_VERSION_NOT_SUPPORTED = {
  code: 39,
  message: 'A crypto handshake message specified an unsupported version.'
}

errors.CRYPTO_HANDSHAKE_STATELESS_REJECT = {
  code: 72,
  message: 'A crypto handshake message resulted in a stateless reject.'
}

errors.CRYPTO_NO_SUPPORT = {
  code: 40,
  message: 'There was no intersection between the crypto primitives supported by the peer and ourselves.'
}

errors.CRYPTO_TOO_MANY_REJECTS = {
  code: 41,
  message: 'The server rejected our client hello messages too many times.'
}

errors.PROOF_INVALID = {
  code: 42,
  message: 'The client rejected the server\'s certificate chain or signature.'
}

errors.CRYPTO_DUPLICATE_TAG = {
  code: 43,
  message: 'A crypto message was received with a duplicate tag.'
}

errors.CRYPTO_ENCRYPTION_LEVEL_INCORRECT = {
  code: 44,
  // i.e. it should have been encrypted but was not.
  message: 'A crypto message was received with the wrong encryption level'
}

errors.CRYPTO_SERVER_CONFIG_EXPIRED = {
  code: 45,
  message: 'The server config for a server has expired.'
}

errors.CRYPTO_SYMMETRIC_KEY_SETUP_FAILED = {
  code: 53,
  message: 'We failed to setup the symmetric keys for a connection.'
}

errors.CRYPTO_MESSAGE_WHILE_VALIDATING_CLIENT_HELLO = {
  code: 54,
  message: 'A handshake message arrived, but we are still validating the previous handshake message.'
}

errors.CRYPTO_UPDATE_BEFORE_HANDSHAKE_COMPLETE = {
  code: 65,
  message: 'A server config update arrived before the handshake is complete.'
}

errors.CRYPTO_CHLO_TOO_LARGE = {
  code: 90,
  message: 'CHLO cannot fit in one packet.'
}

errors.VERSION_NEGOTIATION_MISMATCH = {
  code: 55,
  message: 'This connection involved a version negotiation which appears to have been tampered with.'
}

// Multipath errors.

errors.BAD_MULTIPATH_FLAG = {
  code: 79,
  message: 'Multipath is not enabled, but a packet with multipath flag on is received.'
}

errors.MULTIPATH_PATH_DOES_NOT_EXIST = {
  code: 91,
  message: 'A path is supposed to exist but does not.'
}

errors.MULTIPATH_PATH_NOT_ACTIVE = {
  code: 92,
  message: 'A path is supposed to be active but is not.'
}

errors.IP_ADDRESS_CHANGED = {
  code: 80,
  message: 'IP address changed causing connection close.'
}

// Connection migration errors.

errors.CONNECTION_MIGRATION_NO_MIGRATABLE_STREAMS = {
  code: 81,
  message: 'Network changed, but connection had no migratable streams.'
}

errors.CONNECTION_MIGRATION_TOO_MANY_CHANGES = {
  code: 82,
  message: 'Connection changed networks too many times.'
}

errors.CONNECTION_MIGRATION_NO_NEW_NETWORK = {
  code: 83,
  message: 'Connection migration was attempted, but there was no new network to migrate to.'
}

errors.CONNECTION_MIGRATION_NON_MIGRATABLE_STREAM = {
  code: 84,
  message: 'Network changed, but connection had one or more non-migratable streams.'
}

errors.TOO_MANY_FRAME_GAPS = {
  code: 93,
  message: 'Stream frames arrived too discontiguously so that stream sequencer buffer maintains too many gaps.'
}

// No error. Used as bound while iterating.
errors.LAST_ERROR = {
  code: 94,
  message: 'No error.'
}

for (let key of Object.keys(errors)) {
  let error = errors[key]
  error.name = key
  errors[error.code] = error
}

module.exports = QuicError
