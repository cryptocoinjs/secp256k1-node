'use strict'

var BN = require('bn.js')

var assert = require('./assert')
var messages = require('./messages.json')
var ecparams = require('./ecparams')

/**
 * @param {Buffer} signature
 * @return {Buffer}
 */
exports.signatureNormalize = function (signature) {
  assert.isBuffer(signature, messages.ECDSA_SIGNATURE_TYPE_INVALID)
  assert.isBufferLength(signature, 64, messages.ECDSA_SIGNATURE_LENGTH_INVALID)

  var r = new BN(signature.slice(0, 32))
  var s = new BN(signature.slice(32, 64))
  if (r.cmp(ecparams.N) >= 0 || s.cmp(ecparams.N) >= 0) {
    throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL)
  }

  var result = new Buffer(signature)
  if (s.cmp(ecparams.NH) === 1) {
    new Buffer(ecparams.N.sub(s).toArray(null, 32)).copy(result, 32)
  }

  return result
}

/**
 * @param {Buffer} signature
 * @return {Buffer}
 */
exports.signatureExport = function (signature) {
  assert.isBuffer(signature, messages.ECDSA_SIGNATURE_TYPE_INVALID)
  assert.isBufferLength(signature, 64, messages.ECDSA_SIGNATURE_LENGTH_INVALID)

  var r = Buffer.concat([new Buffer([0]), signature.slice(0, 32)])
  var s = Buffer.concat([new Buffer([0]), signature.slice(32, 64)])
  if (new BN(r).cmp(ecparams.N) >= 0 || new BN(s).cmp(ecparams.N) >= 0) {
    throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL)
  }

  var lenR = 33
  var posR = 0
  while (lenR > 1 && r[posR] === 0x00 && r[posR + 1] < 0x80) {
    --lenR
    ++posR
  }

  var lenS = 33
  var posS = 0
  while (lenS > 1 && s[posS] === 0x00 && s[posS + 1] < 0x80) {
    --lenS
    ++posS
  }

  var result = new Buffer(lenR + lenS + 6)
  result[0] = 0x30
  result[1] = 4 + lenR + lenS
  result[2] = 0x02
  result[3] = lenR
  r.copy(result, 4, posR)
  result[lenR + 4] = 0x02
  result[lenR + 5] = lenS
  s.copy(result, lenR + 6, posS)

  return result
}

/**
 * @param {Buffer} signature
 * @return {Buffer}
 */
exports.signatureImport = function (signature) {
  assert.isBuffer(signature, messages.ECDSA_SIGNATURE_TYPE_INVALID)
  assert.isLengthGTZero(signature, messages.ECDSA_SIGNATURE_LENGTH_INVALID)

  do {
    var length = signature.length
    var index = 0

    if (length < index || signature[index++] !== 0x30) {
      break
    }

    if (length < index || signature[index] > 0x80) {
      break
    }

    var len = signature[index++]
    if (index + len !== length) {
      break
    }

    if (signature[index++] !== 0x02) {
      break
    }

    var rlen = signature[index++]
    if (rlen === 0 || rlen > 33 ||
        (signature[index] === 0x00 && rlen > 1 && signature[index + 1] < 0x80) ||
        (signature[index] === 0xff && rlen > 1 && signature[index + 1] >= 0x80)) {
      break
    }
    var r = new BN(signature.slice(index, index + rlen))
    if (r.cmp(ecparams.N) >= 0) {
      r = new BN(0)
    }
    index += rlen

    if (signature[index++] !== 0x02) {
      break
    }

    var slen = signature[index++]
    if (slen === 0 || slen > 33 ||
        (signature[index] === 0x00 && slen > 1 && signature[index + 1] < 0x80) ||
        (signature[index] === 0xff && slen > 1 && signature[index + 1] >= 0x80)) {
      break
    }
    var s = new BN(signature.slice(index, index + slen))
    if (s.cmp(ecparams.N) >= 0) {
      s = new BN(0)
    }

    var result = new Buffer(64)
    new Buffer(r.toArray(null, 32)).copy(result, 0)
    new Buffer(s.toArray(null, 32)).copy(result, 32)
    return result
  } while (false)

  throw new Error(messages.ECDSA_SIGNATURE_PARSE_DER_FAIL)
}
