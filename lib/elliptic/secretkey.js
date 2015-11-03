var BN = require('bn.js')

var asserts = require('../asserts')
var messages = require('../messages')
var util = require('./util')

/**
 * Verify an ECDSA secret key.
 * @method verifySecetKey
 * @param {Buffer} secretKey the secret Key to verify
 * @return {boolean} `true` if secret key is valid, `false` otherwise
 */
exports.secretKeyVerify = function (secretKey) {
  asserts.checkTypeBuffer(secretKey, messages.EC_PRIVKEY_TYPE_INVALID)

  return secretKey.length === 32 && util.isValidSecretKey(secretKey)
}

/**
 * Export a secret key in DER format.
 * @method secretKeyExport
 * @param {Buffer} secretKey the secret key to export
 * @param {boolean} [compressed=true]
 * @return {Buffer}
 */
exports.secretKeyExport = function () {
  throw new Error('Not implemented now.')
}

/**
 * Import a secret key in DER format.
 * @method secretKeyImport
 * @param {Buffer} secretKey the secret key to import
 * @return {Buffer}
 */
exports.secretKeyImport = function () {
  throw new Error('Not implemented now.')
}

/**
 * Tweak a secret key by adding tweak to it.
 * @method secretKeyTweakAdd
 * @param {Buffer} secretKey
 * @param {Buffer} tweak
 * @return {Buffer}
 */
exports.secretKeyTweakAdd = function (secretKey, tweak) {
  asserts.checkTypeBuffer(secretKey, messages.EC_PRIVKEY_TYPE_INVALID)
  asserts.checkBufferLength(secretKey, 32, messages.EC_PRIVKEY_LENGTH_INVALID)

  asserts.checkTypeBuffer(tweak, messages.TWEAK_TYPE_INVALID)
  asserts.checkBufferLength(tweak, 32, messages.TWEAK_LENGTH_INVALID)

  var bn = new BN(tweak)
  if (util.isOverflow(bn)) {
    throw new Error(messages.EC_PRIVKEY_TWEAK_ADD_FAIL)
  }

  bn = util.bnReduce(bn.iadd(new BN(secretKey)))
  if (util.isZero(bn)) {
    throw new Error(messages.EC_PRIVKEY_TWEAK_ADD_FAIL)
  }

  return new Buffer(bn.toArray(null, 32))
}

/**
 * Tweak a secret key by multiplying tweak to it.
 * @method secretKeyTweakMul
 * @param {Buffer} secretKey
 * @param {Buffer} tweak
 * @return {Buffer}
 */
exports.secretKeyTweakMul = function (secretKey, tweak) {
  asserts.checkTypeBuffer(secretKey, messages.EC_PRIVKEY_TYPE_INVALID)
  asserts.checkBufferLength(secretKey, 32, messages.EC_PRIVKEY_LENGTH_INVALID)

  asserts.checkTypeBuffer(tweak, messages.TWEAK_TYPE_INVALID)
  asserts.checkBufferLength(tweak, 32, messages.TWEAK_LENGTH_INVALID)

  var bn = new BN(tweak)
  if (util.isOverflow(bn) || util.isZero(bn)) {
    throw new Error(messages.EC_PRIVKEY_TWEAK_MUL_FAIL)
  }

  bn = util.bnReduce(bn.imul(new BN(secretKey)))
  return new Buffer(bn.toArray(null, 32))
}

