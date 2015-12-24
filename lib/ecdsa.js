'use strict'

var BN = require('bn.js')

var assert = require('./assert')
var messages = require('./messages.json')
var util = require('./util')
var ecparams = require('./ecparams')
var ECPoint = require('./ecpoint')
var nonce_function_rfc6979 = require('./rfc6979')

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
 * @param {sign~noncefn} [noncefn=nonce_function_rfc6979]
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

  var data = null
  var noncefn = nonce_function_rfc6979
  if (options !== undefined) {
    assert.isObject(options, messages.OPTIONS_TYPE_INVALID)

    if (options.data !== undefined) {
      assert.isBuffer(options.data, messages.OPTIONS_DATA_TYPE_INVALID)
      assert.isBufferLength(options.data, 32, messages.OPTIONS_DATA_LENGTH_INVALID)
      data = options.data
    }

    if (options.noncefn !== undefined) {
      assert.isFunction(options.noncefn, messages.OPTIONS_NONCEFN_TYPE_INVALID)
      noncefn = options.noncefn
    }
  }

  var d = new BN(privateKey)
  if (d.cmp(ecparams.N) >= 0 || d.cmpn(0) === 0) {
    throw new Error(messages.ECDSA_SIGN_FAIL)
  }

  var bnMessage = new BN(message)
  for (var count = 0; ; ++count) {
    var k = noncefn(message, privateKey, null, data, count)
    if (!Buffer.isBuffer(k) || k.length !== 32) {
      throw new Error(messages.ECDSA_SIGN_FAIL)
    }

    k = new BN(k)
    if (k.cmp(ecparams.N) >= 0 || k.cmpn(0) === 0) {
      continue
    }

    var kp = ecparams.G.mul(k)
    var r = kp.x.umod(ecparams.N)
    if (r.cmpn(0) === 0) {
      continue
    }

    var s = k.invm(ecparams.N).mul(r.mul(d).iadd(bnMessage)).umod(ecparams.N)
    if (s.cmpn(0) === 0) {
      continue
    }

    var recovery = (kp.x.cmp(r) !== 0 ? 2 : 0) | (kp.y.isOdd() ? 1 : 0)
    if (s.cmp(ecparams.NH) > 0) {
      s = ecparams.N.sub(s)
      recovery ^= 1
    }

    return {
      signature: new Buffer(r.toArray(null, 32).concat(s.toArray(null, 32))),
      recovery: recovery
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

  var sigr = new BN(signature.slice(0, 32))
  var sigs = new BN(signature.slice(32, 64))
  if (sigr.cmp(ecparams.N) >= 0 || sigs.cmp(ecparams.N) >= 0) {
    throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL)
  }

  if (sigs.cmp(ecparams.NH) === 1 ||
      sigr.cmpn(0) === 0 || sigs.cmpn(0) === 0) {
    return false
  }

  var pub = ECPoint.fromPublicKey(publicKey)
  if (pub === null) {
    throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)
  }

  var sinv = sigs.invm(ecparams.N)
  var u1 = sinv.mul(new BN(message)).umod(ecparams.N)
  var u2 = sinv.mul(sigr).umod(ecparams.N)
  var point = ecparams.G.mulAdd(u1, pub, u2)
  if (point.isInfinity()) {
    return false
  }

  return point.x.umod(ecparams.N).cmp(sigr) === 0
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

  var sigr = new BN(signature.slice(0, 32))
  var sigs = new BN(signature.slice(32, 64))
  if (sigr.cmp(ecparams.N) >= 0 || sigs.cmp(ecparams.N) >= 0) {
    throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL)
  }

  do {
    if (sigr.cmpn(0) === 0 || sigs.cmpn(0) === 0) {
      break
    }

    var kpx = sigr
    if (recovery >> 1) {
      if (kpx.cmp(ecparams.P.umod(ecparams.N)) >= 0) {
        break
      }

      kpx = sigr.add(ecparams.N)
    }

    var kpPublicKey = new Buffer([0x02 + (recovery & 0x01)].concat(kpx.toArray(null, 32)))
    var kp = ECPoint.fromPublicKey(kpPublicKey)
    var eNeg = ecparams.N.sub(new BN(message))
    var rInv = sigr.invm(ecparams.N)
    return kp.mul(sigs).add(ecparams.G.mul(eNeg)).mul(rInv).toPublicKey(compressed)
  } while (false)

  throw new Error(messages.ECDSA_RECOVER_FAIL)
}
