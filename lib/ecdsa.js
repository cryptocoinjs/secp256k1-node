'use strict'

var assert = require('./lib/assert')
var messages = require('./lib/messages.json')
var util = require('./lib/util')

/**
 * @callback sign~noncefn
 * @param {Buffer} message
 * @param {Buffer} privateKey
 * @param {?Buffer} algo
 * @param {?Buffer} data
 * @param {number} attempt
 * @return {Buffer}
 */

/**
 * @typedef {Object} sign~options
 * @param {Buffer} [data]
 * @param {sign~noncefn} [noncefn=secp256k1_nonce_function_rfc6979]
 */

/**
 * @param {Buffer} message
 * @param {Buffer} privateKey
 * @param {sign~options} [options]
 * @return {{signature: Buffer, recovery: number}}
 */
exports.sign = function (message, privateKey, options) {
  assert.isBuffer(message, messages.MSG32_TYPE_INVALID)
  assert.isBufferLength(message, 32, messages.MSG32_LENGTH_INVALID)

  assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID)
  assert.isBufferLength(privateKey, 32, messages.EC_PRIVATE_KEY_LENGTH_INVALID)

  if (options !== undefined) {
    assert.isObject(options, messages.OPTIONS_TYPE_INVALID)

    if (options.data !== undefined) {
      assert.isBuffer(options.data, messages.OPTIONS_DATA_TYPE_INVALID)
      assert.isBufferLength(options.data, 32, messages.OPTIONS_DATA_LENGTH_INVALID)
    }

    if (options.noncefn !== undefined) {
      assert.isFunction(options.noncefn, messages.OPTIONS_NONCEFN_TYPE_INVALID)
    }
  }
}

/**
 * @param {Buffer} message
 * @param {Buffer} signature
 * @param {Buffer} publicKey
 * @return {boolean}
 */
exports.verify = function (message, signature, publicKey) {
  assert.isBuffer(message, messages.MSG32_TYPE_INVALID)
  assert.isBufferLength(message, 32, messages.MSG32_LENGTH_INVALID)

  assert.isBuffer(signature, messages.ECDSA_SIGNATURE_TYPE_INVALID)
  assert.isBufferLength(signature, 64, messages.ECDSA_SIGNATURE_LENGTH_INVALID)

  assert.isBuffer(publicKey, messages.EC_PUBLIC_KEY_TYPE_INVALID)
  assert.isBufferLength2(publicKey, 33, 65, messages.EC_PUBLIC_KEY_LENGTH_INVALID)
}

/**
 * @param {Buffer} message
 * @param {Buffer} signature
 * @param {number} recovery
 * @param {boolean} [compressed=true]
 * @return {Buffer}
 */
exports.recover = function (message, signature, recovery, compressed) {
  assert.isBuffer(message, messages.MSG32_TYPE_INVALID)
  assert.isBufferLength(message, 32, messages.MSG32_LENGTH_INVALID)

  assert.isBuffer(signature, messages.ECDSA_SIGNATURE_TYPE_INVALID)
  assert.isBufferLength(signature, 64, messages.ECDSA_SIGNATURE_LENGTH_INVALID)

  assert.isNumber(recovery, messages.RECOVERY_ID_TYPE_INVALID)
  assert.isNumberInInterval(recovery, -1, 4, messages.RECOVERY_ID_VALUE_INVALID)

  compressed = util.initCompressedValue(compressed, true)
}
