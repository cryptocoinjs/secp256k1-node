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
  if (r.cmp(ecparams.n) >= 0 || s.cmp(ecparams.n) >= 0) {
    throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL)
  }

  var result = new Buffer(signature)
  if (s.cmp(ecparams.nh) === 1) {
    new Buffer(ecparams.n.sub(s).toArray(null, 32)).copy(result, 32)
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
  if (new BN(r).cmp(ecparams.n) >= 0 || new BN(s).cmp(ecparams.n) >= 0) {
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
 * @param {Object} o
 * @param {Buffer} o.sig
 * @param {number} o.idx
 * @return {?BN}
 */
function parseScalar (o) {
  if (o.sig[o.idx++] !== 0x02) {
    return null
  }

  var rlen = o.sig[o.idx++]
  if (rlen === 0 || rlen > 33 ||
      (rlen > 1 &&
       (o.sig[o.idx] === 0x00 && o.sig[o.idx + 1] < 0x80) ||
       (o.sig[o.idx] === 0xff && o.sig[o.idx + 1] >= 0x80))) {
    return null
  }

  if (o.sig[o.idx] === 0 && rlen === 33) {
    o.idx += 1
    rlen -= 1
  }

  o.idx += rlen
  if (rlen <= 32) {
    var b = new Buffer(32)
    for (var i = 0; i < 32 - rlen; ++i) {
      b[i] = 0
    }
    o.sig.slice(o.idx - rlen, o.idx).copy(b, 32 - rlen)
    var r = new BN(b)
    if (r.cmp(ecparams.n) === -1) {
      return r
    }

    return BN(0)
  }

  return BN(0)
}

/**
 * @param {Buffer} signature
 * @return {Buffer}
 */
exports.signatureImport = function (signature) {
  assert.isBuffer(signature, messages.ECDSA_SIGNATURE_TYPE_INVALID)
  assert.isLengthGTZero(signature, messages.ECDSA_SIGNATURE_LENGTH_INVALID)

  do {
    var o = {sig: signature, idx: 0}
    if ((o.sig.length < o.idx || o.sig[o.idx] !== 0x30) ||
        (o.sig.length < o.idx + 1 || o.sig[o.idx + 1] > 0x80) ||
        o.idx + o.sig[o.idx + 1] + 2 !== o.sig.length) {
      break
    }
    o.idx += 2

    var r = parseScalar(o)
    if (r === null) {
      break
    }

    var s = parseScalar(o)
    if (s === null) {
      break
    }

    var result = new Buffer(64)
    new Buffer(r.toArray(null, 32)).copy(result, 0)
    new Buffer(s.toArray(null, 32)).copy(result, 32)
    return result
  } while (false)

  throw new Error(messages.ECDSA_SIGNATURE_PARSE_DER_FAIL)
}
