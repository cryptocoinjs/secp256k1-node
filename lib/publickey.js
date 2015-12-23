'use strict'

var BN = require('bn.js')

var assert = require('./assert')
var messages = require('./messages.json')
var util = require('./util')
var ecparams = require('./ecparams')
var ECPoint = require('./ecpoint')

/**
 * @param {Buffer} privateKey
 * @param {boolean} [compressed=true]
 * @return {Buffer}
 */
exports.publicKeyCreate = function (privateKey, compressed) {
  assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID)
  assert.isBufferLength(privateKey, 32, messages.EC_PRIVATE_KEY_LENGTH_INVALID)

  compressed = util.initCompressedValue(compressed, true)

  var bn = new BN(privateKey)
  if (bn.cmp(ecparams.N) >= 0 || bn.cmpn(0) === 0) {
    throw new Error(messages.EC_PUBLIC_KEY_CREATE_FAIL)
  }

  return ecparams.G.mul(bn).toPublicKey(compressed)
}

/**
 * @param {Buffer} publicKey
 * @param {boolean} [compressed=true]
 * @return {Buffer}
 */
exports.publicKeyConvert = function (publicKey, compressed) {
  assert.isBuffer(publicKey, messages.EC_PUBLIC_KEY_TYPE_INVALID)
  assert.isBufferLength2(publicKey, 33, 65, messages.EC_PUBLIC_KEY_LENGTH_INVALID)

  compressed = util.initCompressedValue(compressed, true)

  var point = ECPoint.fromPublicKey(publicKey)
  if (point === null) {
    throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)
  }

  return point.toPublicKey(compressed)
}

/**
 * @param {Buffer} publicKey
 * @return {boolean}
 */
exports.publicKeyVerify = function (publicKey) {
  assert.isBuffer(publicKey, messages.EC_PUBLIC_KEY_TYPE_INVALID)
  return ECPoint.fromPublicKey(publicKey) !== null
}

/**
 * @param {Buffer} publicKey
 * @param {Buffer} tweak
 * @param {boolean} [compressed=true]
 * @return {Buffer}
 */
exports.publicKeyTweakAdd = function (publicKey, tweak, compressed) {
  assert.isBuffer(publicKey, messages.EC_PUBLIC_KEY_TYPE_INVALID)
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
  assert.isBuffer(publicKey, messages.EC_PUBLIC_KEY_TYPE_INVALID)
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

  var points = new Array(publicKeys.length)
  for (var i = 0; i < publicKeys.length; ++i) {
    assert.isBuffer(publicKeys[i], messages.EC_PUBLIC_KEY_TYPE_INVALID)
    assert.isBufferLength2(publicKeys[i], 33, 65, messages.EC_PUBLIC_KEY_LENGTH_INVALID)

    points[i] = ECPoint.fromPublicKey(publicKeys[i])
    if (points[i] === null) {
      throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)
    }
  }

  var point = points[0]
  for (var j = 1; j < points.length; ++j) {
    point = point.add(points[j])
  }

  if (point.inf) {
    throw new Error(messages.EC_PUBLIC_KEY_COMBINE_FAIL)
  }

  return point.toPublicKey(compressed)
}
