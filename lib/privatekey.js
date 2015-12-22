'use strict'

var BN = require('bn.js')

var assert = require('./assert')
var messages = require('./messages.json')
var util = require('./util')
var ec = require('./ec')

var EC_PRIVKEY_EXPORT_DER_COMPRESSED_BEGIN = new Buffer(
  '3081d30201010420', 'hex')
var EC_PRIVKEY_EXPORT_DER_COMPRESSED_MIDDLE = new Buffer(
  'a08185308182020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f300604010004010704210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101a124032200', 'hex')
var EC_PRIVKEY_EXPORT_DER_UNCOMPRESSED_BEGIN = new Buffer(
  '308201130201010420', 'hex')
var EC_PRIVKEY_EXPORT_DER_UNCOMPRESSED_MIDDLE = new Buffer(
  'a081a53081a2020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f300604010004010704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101a144034200', 'hex')

/**
 * @param {Buffer} privateKey
 * @return {boolean}
 */
exports.privateKeyVerify = function (privateKey) {
  assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID)
  return privateKey.length === 32 && ec.isValidPrivateKey(privateKey)
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

  do {
    var length = privateKey.length

    // sequence header
    var index = 0
    if (length < index + 1 || privateKey[index] !== 0x30) {
      break
    }
    index += 1

    // sequence length constructor
    if (length < index + 1 || !(privateKey[index] & 0x80)) {
      break
    }

    var lenb = privateKey[index] & 0x7f
    index += 1
    if (lenb < 1 || lenb > 2) {
      break
    }
    if (length < index + lenb) {
      break
    }

    // sequence length
    var len = privateKey[index + lenb - 1] | (lenb > 1 ? privateKey[index + lenb - 2] << 8 : 0)
    index += lenb
    if (length < index + len) {
      break
    }

    // sequence element 0: version number (=1)
    if (length < index + 3 ||
        privateKey[index] !== 0x02 ||
        privateKey[index + 1] !== 0x01 ||
        privateKey[index + 2] !== 0x01) {
      break
    }
    index += 3

    // sequence element 1: octet string, up to 32 bytes
    if (length < index + 2 ||
        privateKey[index] !== 0x04 ||
        privateKey[index + 1] > 0x20 ||
        length < index + 2 + privateKey[index + 1]) {
      break
    }

    privateKey = privateKey.slice(index + 2, index + 2 + privateKey[index + 1])
    if (privateKey.length === 32 && ec.isValidPrivateKey(privateKey)) {
      return privateKey
    }
  } while (false)

  throw new Error(messages.EC_PRIVATE_KEY_IMPORT_DER_FAIL)
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

  var bn = new BN(tweak)
  if (bn.cmp(ec.N) >= 0) {
    throw new Error(messages.EC_PRIVATE_KEY_TWEAK_ADD_FAIL)
  }

  bn.iadd(new BN(privateKey))
  if (bn.cmp(ec.N) >= 0) {
    bn.isub(ec.N)
  }

  if (bn.cmpn(0) === 0) {
    throw new Error(messages.EC_PRIVATE_KEY_TWEAK_ADD_FAIL)
  }

  return new Buffer(bn.toArray(null, 32))
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

  var bn = new BN(tweak)
  if (bn.cmp(ec.N) >= 0 || bn.cmpn(0) === 0) {
    throw new Error(messages.EC_PRIVATE_KEY_TWEAK_MUL_FAIL)
  }

  bn.imul(new BN(privateKey))
  if (bn.cmp(ec.N) >= 0) {
    bn = bn.mod(ec.N)
  }

  return new Buffer(bn.toArray(null, 32))
}
