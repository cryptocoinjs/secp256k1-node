var asserts = require('../asserts')
var messages = require('../messages')
var ec = require('./ec')
var util = require('./util')

/**
 * Synchronous .sign
 * @method signSync
 * @param {Buffer} msg
 * @param {Buffer} secretKey
 * @return {{signature: Buffer, recovery: number}}
 */
exports.signSync = function (msg, secretKey) {
  asserts.checkTypeBuffer(msg, messages.MSG32_TYPE_INVALID)
  asserts.checkBufferLength(msg, 32, messages.MSG32_LENGTH_INVALID)

  asserts.checkTypeBuffer(secretKey, messages.EC_PRIVKEY_TYPE_INVALID)
  asserts.checkBufferLength(secretKey, 32, messages.EC_PRIVKEY_LENGTH_INVALID)

  if (!util.isValidSecretKey(secretKey)) {
    throw new Error(messages.ECDSA_SIGN_FAIL)
  }

  var result = ec.sign(msg, secretKey, {canonical: true})

  // https://github.com/indutny/elliptic/issues/59
  result.recoveryParam = null
  var recid = ec.getKeyRecoveryParam(msg, result, ec.keyFromPrivate(secretKey).getPublic())

  return {
    signature: new Buffer(result.r.toArray('be', 32).concat(result.s.toArray('be', 32))),
    recovery: recid
  }
}

