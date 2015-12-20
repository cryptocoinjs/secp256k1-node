'use strict'

var assert = require('./lib/assert')
var messages = require('./lib/messages.json')
var util = require('./lib/util')

/**
 * @param {Buffer} privateKey
 * @param {boolean} [compressed=true]
 * @return {Buffer}
 */
exports.publicKeyCreate = function (privateKey, compressed) {
  assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID)
  assert.isBufferLength(privateKey, 32, messages.EC_PRIVATE_KEY_LENGTH_INVALID)

  compressed = util.initCompressedValue(compressed, true)
}

/**
 * @param {Buffer} publicKey
 * @param {boolean} [compressed=true]
 * @return {Buffer}
 */
exports.publicKeyConvert = function (publicKey, compressed) {
  assert.isBuffer(publicKey, messages.EC_PRIVATE_KEY_TYPE_INVALID)
  assert.isBufferLength2(publicKey, 33, 65, messages.EC_PUBLIC_KEY_LENGTH_INVALID)

  compressed = util.initCompressedValue(compressed, true)
}

/**
 * @param {Buffer} publicKey
 * @return {boolean}
 */
exports.publicKeyVerify = function (publicKey) {
  assert.isBuffer(publicKey, messages.EC_PRIVATE_KEY_TYPE_INVALID)
}

/**
 * @param {Buffer} publicKey
 * @param {Buffer} tweak
 * @param {boolean} [compressed=true]
 * @return {Buffer}
 */
exports.publicKeyTweakAdd = function (publicKey, tweak, compressed) {
  assert.isBuffer(publicKey, messages.EC_PRIVATE_KEY_TYPE_INVALID)
  assert.isBufferLength2(publicKey, 33, 65, messages.EC_PUBLIC_KEY_LENGTH_INVALID)

  assert.isBuffer(tweak, messages.TWEAK_TYPE_INVALID)
  assert.isBufferLength(tweak, 32, messages.TWEAK_LENGTH_INVALID)

  compressed = util.initCompressedValue(compressed, true)
}

/**
 * @param {Buffer} publicKey
 * @param {Buffer} tweak
 * @param {boolean} [compressed=true]
 * @return {Buffer}
 */
exports.publicKeyTweakMul = function (publicKey, tweak, compressed) {
  assert.isBuffer(publicKey, messages.EC_PRIVATE_KEY_TYPE_INVALID)
  assert.isBufferLength2(publicKey, 33, 65, messages.EC_PUBLIC_KEY_LENGTH_INVALID)

  assert.isBuffer(tweak, messages.TWEAK_TYPE_INVALID)
  assert.isBufferLength(tweak, 32, messages.TWEAK_LENGTH_INVALID)

  compressed = util.initCompressedValue(compressed, true)
}

/**
 * @param {Buffer[]} publicKeys
 * @param {boolean} [compressed=true]
 * @return {Buffer}
 */
exports.publicKeyCombine = function (publicKeys, compressed) {
  assert.isArray(publicKeys, messages.EC_PUBLIC_KEYS_TYPE_INVALID)
  assert.isLengthGTZero(publicKeys, messages.EC_PUBLIC_KEYS_LENGTH_INVALID)

  compressed = util.initCompressedValue(compressed, true)
}
