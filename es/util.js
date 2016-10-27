import * as messages from './messages.json'

const toString = Object.prototype.toString

// TypeError
export function checkTypeArray (value, message) {
  if (!Array.isArray(value)) throw TypeError(message)
}

export function checkTypeFunction (value, message) {
  if (toString.call(value) !== '[object Function]') throw TypeError(message)
}

export function checkTypeBuffer (value, message) {
  if (!Buffer.isBuffer(value)) throw TypeError(message)
}

export function checkTypeBoolean (value, message) {
  if (toString.call(value) !== '[object Boolean]') throw TypeError(message)
}

export function checkTypeNumber (value, message) {
  if (toString.call(value) !== '[object Number]') throw TypeError(message)
}

// RangeError
export function checkLength (buffer, length, message) {
  if (buffer.length !== length) throw RangeError(message)
}

export function checkLength2 (buffer, length1, length2, message) {
  if (buffer.length !== length1 && buffer.length !== length2) throw RangeError(message)
}

export function checkLengthGTZero (value, message) {
  if (value.length === 0) throw RangeError(message)
}

export function checkInInterval (number, x, y, message) {
  if (number < x || number > y) throw RangeError(message)
}

// arguments
export function handleArgPrivateKey (value) {
  checkTypeBuffer(value, messages.EC_PRIVATE_KEY_TYPE_INVALID)
  checkLength(value, 32, messages.EC_PRIVATE_KEY_LENGTH_INVALID)
}

export function handleArgPublicKey (value) {
  checkTypeBuffer(value, messages.EC_PUBLIC_KEY_TYPE_INVALID)
  checkLength2(value, 33, 65, messages.EC_PUBLIC_KEY_LENGTH_INVALID)
}

export function handleArgMessage (value) {
  checkTypeBuffer(value, messages.MESSAGE_TYPE_INVALID)
  checkLength(value, 32, messages.MESSAGE_LENGTH_INVALID)
}

export function handleArgECDSASignatureRaw (value) {
  checkTypeBuffer(value, messages.ECDSA_SIGNATURE_TYPE_INVALID)
  checkLength(value, 64, messages.ECDSA_SIGNATURE_LENGTH_INVALID)
}

export function handleArgECDSASignatureDer (value) {
  checkTypeBuffer(value, messages.ECDSA_SIGNATURE_TYPE_INVALID)
  checkLengthGTZero(value, messages.ECDSA_SIGNATURE_LENGTH_INVALID)
}

export function handleArgSchnorrSignature (value) {
  checkTypeBuffer(value, messages.SCHNORR_SIGNATURE_TYPE_INVALID)
  checkLength(value, 64, messages.SCHNORR_SIGNATURE_LENGTH_INVALID)
}

export function handleArgTweak (value) {
  checkTypeBuffer(value, messages.TWEAK_TYPE_INVALID)
  checkLength(value, 32, messages.TWEAK_LENGTH_INVALID)
}

export function handleArgNonceFunction (value) {
  if (value !== undefined) checkTypeFunction(value, messages.NONCE_FUNCTION_TYPE_INVALID)
}

export function handleArgNonceData (value) {
  if (value !== undefined) {
    checkTypeBuffer(value, messages.NONCE_DATA_TYPE_INVALID)
    checkLength(value, 32, messages.NONCE_DATA_LENGTH_INVALID)
  }
}

export function handleArgCompressed (value) {
  checkTypeBoolean(value, messages.COMPRESSED_TYPE_INVALID)
}
