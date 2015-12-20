'use strict'

var assert = require('./lib/assert')
var messages = require('./lib/messages.json')

/**
 * @param {Buffer} publicKey
 * @param {Buffer} privateKey
 * @param {?} options
 * @return {Buffer}
 */
exports.ecdh = function (publicKey, privateKey, options) {
  assert.isBuffer(publicKey, messages.EC_PUBLIC_KEY_TYPE_INVALID)
  assert.isBufferLength2(publicKey, 33, 65, messages.EC_PUBLIC_KEY_LENGTH_INVALID)

  assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID)
  assert.isBufferLength(privateKey, 32, messages.EC_PRIVATE_KEY_LENGTH_INVALID)

  if (options !== undefined) {
    assert.isObject(options, messages.OPTIONS_TYPE_INVALID)
  }
}
