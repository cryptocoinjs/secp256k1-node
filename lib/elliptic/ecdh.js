var asserts = require('../asserts')
var messages = require('../messages')

/**
 * Synchronous .ecdh
 * @method recoverSync
 * @param {Buffer} publicKey
 * @param {Buffer} secretKey
 * @return {Buffer}
 */
exports.ecdhSync = function (publicKey, secretKey) {
  asserts.checkTypeBuffer(publicKey, messages.EC_PUBKEY_TYPE_INVALID)
  asserts.checkBufferLength2(publicKey, 33, 65, messages.EC_PUBKEY_LENGTH_INVALID)

  asserts.checkTypeBuffer(secretKey, messages.EC_PRIVKEY_TYPE_INVALID)
  asserts.checkBufferLength(secretKey, 32, messages.EC_PRIVKEY_LENGTH_INVALID)

  // TODO
}

