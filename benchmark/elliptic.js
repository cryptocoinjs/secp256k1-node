'use strict'

var EC = require('elliptic').ec
var ec = new EC('secp256k1')

/**
 * @param {Buffer} message
 * @param {Buffer} privateKey
 * @return {{signature: string, recovery: number}}
 */
exports.sign = function (message, privateKey) {
  // asserts.checkTypeBuffer(message, messages.MSG32_TYPE_INVALID)
  // asserts.checkBufferLength(message, 32, messages.MSG32_LENGTH_INVALID)
  //
  // asserts.checkTypeBuffer(privateKey, messages.EC_PRIVKEY_TYPE_INVALID)
  // asserts.checkBufferLength(privateKey, 32, messages.EC_PRIVKEY_LENGTH_INVALID)
  //
  // if (!util.isValidSecretKey(privateKey)) {
  //   throw new Error(messages.ECDSA_SIGN_FAIL)
  // }

  var result = ec.sign(message, privateKey, {canonical: true})
  return {
    signature: new Buffer(result.r.toArray(null, 32).concat(result.s.toArray(null, 32))),
    recovery: result.recoveryParam
  }
}

/**
 * @param {Buffer} message
 * @param {Buffer} signature
 * @param {Buffer} publicKey
 * @return {boolean}
 */
exports.verify = function (message, signature, publicKey) {
  // asserts.checkTypeBuffer(message, messages.MSG32_TYPE_INVALID)
  // asserts.checkBufferLength(message, 32, messages.MSG32_LENGTH_INVALID)
  //
  // asserts.checkTypeBuffer(signature, messages.ECDSA_SIGNATURE_TYPE_INVALID)
  // asserts.checkBufferLength(signature, 64, messages.ECDSA_SIGNATURE_LENGTH_INVALID)
  //
  // asserts.checkTypeBuffer(publicKey, messages.EC_PUBKEY_TYPE_INVALID)
  // asserts.checkBufferLength2(publicKey, 33, 65, messages.EC_PUBKEY_LENGTH_INVALID)
  //
  // if (!util.isValidSignature(signature)) {
  //   throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL)
  // }
  //
  // if (!util.isValidPublicKey(publicKey)) {
  //   throw new Error(messages.EC_PUBKEY_PARSE_FAIL)
  // }

  var sigObj = {r: signature.slice(0, 32), s: signature.slice(32, 64)}
  return ec.verify(message, sigObj, publicKey)
}
