'use strict'

var assert = require('./lib/assert')
var messages = require('./lib/messages.json')
var util = require('./lib/util')

/**
 * @param {Buffer} privateKey
 * @return {boolean}
 */
exports.privateKeyVerify = function (privateKey) {
  assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID)
}

/**
 * @param {Buffer} privateKey
 * @param {boolean} [compressed=true]
 * @return {Buffer}
 */
exports.privateKeyExport = function (privateKey, compressed) {
  assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID)
  assert.isBufferLength(privateKey, 32, messages.EC_PRIVATE_KEY_LENGTH_INVALID)

  compressed = util.initCompressedValue(compressed, true)
}

/**
 * @param {Buffer} privateKey
 * @return {Buffer}
 */
exports.privateKeyImport = function (privateKey) {
  assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID)
  assert.isLengthGTZero(privateKey, messages.EC_PRIVATE_KEY_LENGTH_INVALID)
}

/**
 * @param {Buffer} privateKey
 * @param {Buffer} tweak
 * @return {Buffer}
 */
exports.privateKeyTweakAdd = function (privateKey, tweak) {
  assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID)
  assert.isBufferLength(privateKey, 32, messages.EC_PRIVATE_KEY_LENGTH_INVALID)

  assert.isBuffer(tweak, messages.TWEAK_TYPE_INVALID)
  assert.isBufferLength(tweak, 32, messages.TWEAK_LENGTH_INVALID)
}

/**
 * @param {Buffer} privateKey
 * @param {Buffer} tweak
 * @return {Buffer}
 */
exports.privateKeyTweakMul = function (privateKey, tweak) {
  assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID)
  assert.isBufferLength(privateKey, 32, messages.EC_PRIVATE_KEY_LENGTH_INVALID)

  assert.isBuffer(tweak, messages.TWEAK_TYPE_INVALID)
  assert.isBufferLength(tweak, 32, messages.TWEAK_LENGTH_INVALID)
}
