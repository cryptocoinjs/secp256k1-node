'use strict'

var BN = require('bn.js')

var messages = require('../messages.json')
var nonce_function_rfc6979 = require('./rfc6979')
var ecparams = require('./ecparams')
var ECPoint = require('./ecpoint')
var g = require('./ecpointg')

/**
 * @param {Buffer} privateKey
 * @return {boolean}
 */
exports.privateKeyVerify = function (privateKey) {
  var bn = new BN(privateKey)
  return bn.cmp(ecparams.n) === -1 && bn.cmpn(0) === 1
}

/**
 * @param {Buffer} privateKey
 * @param {boolean} compressed
 * @return {Buffer}
 */
exports.privateKeyExport = function (privateKey, compressed) {
  var d = new BN(privateKey)
  if (d.cmp(ecparams.n) >= 0 || d.cmpn(0) === 0) {
    throw new Error(messages.EC_PRIVATE_KEY_EXPORT_DER_FAIL)
  }

  return g.mul(d).toPublicKey(compressed)
}

/**
 * @param {Buffer} privateKey
 * @param {Buffer} tweak
 * @return {Buffer}
 */
exports.privateKeyTweakAdd = function (privateKey, tweak) {
  var bn = new BN(tweak)
  if (bn.cmp(ecparams.n) >= 0) {
    throw new Error(messages.EC_PRIVATE_KEY_TWEAK_ADD_FAIL)
  }

  bn.iadd(new BN(privateKey))
  if (bn.cmp(ecparams.n) >= 0) {
    bn.isub(ecparams.n)
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
  var bn = new BN(tweak)
  if (bn.cmp(ecparams.n) >= 0 || bn.cmpn(0) === 0) {
    throw new Error(messages.EC_PRIVATE_KEY_TWEAK_MUL_FAIL)
  }

  bn.imul(new BN(privateKey))
  if (bn.cmp(ecparams.n) >= 0) {
    bn = bn.mod(ecparams.n)
  }

  return new Buffer(bn.toArray(null, 32))
}

/**
 * @param {Buffer} privateKey
 * @param {boolean} compressed
 * @return {Buffer}
 */
exports.publicKeyCreate = function (privateKey, compressed) {
  var d = new BN(privateKey)
  if (d.cmp(ecparams.n) >= 0 || d.cmpn(0) === 0) {
    throw new Error(messages.EC_PUBLIC_KEY_CREATE_FAIL)
  }

  return g.mul(d).toPublicKey(compressed)
}

/**
 * @param {Buffer} publicKey
 * @param {boolean} compressed
 * @return {Buffer}
 */
exports.publicKeyConvert = function (publicKey, compressed) {
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
  return ECPoint.fromPublicKey(publicKey) !== null
}

/**
 * @param {Buffer} publicKey
 * @param {Buffer} tweak
 * @param {boolean} compressed
 * @return {Buffer}
 */
exports.publicKeyTweakAdd = function (publicKey, tweak, compressed) {
  var point = ECPoint.fromPublicKey(publicKey)
  if (point === null) {
    throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)
  }

  tweak = new BN(tweak)
  if (tweak.cmp(ecparams.n) >= 0) {
    throw new Error(messages.EC_PUBLIC_KEY_TWEAK_ADD_FAIL)
  }

  return g.mul(tweak).add(point).toPublicKey(compressed)
}

/**
 * @param {Buffer} publicKey
 * @param {Buffer} tweak
 * @param {boolean} compressed
 * @return {Buffer}
 */
exports.publicKeyTweakMul = function (publicKey, tweak, compressed) {
  var point = ECPoint.fromPublicKey(publicKey)
  if (point === null) {
    throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)
  }

  tweak = new BN(tweak)
  if (tweak.cmp(ecparams.n) >= 0 || tweak.cmpn(0) === 0) {
    throw new Error(messages.EC_PUBLIC_KEY_TWEAK_MUL_FAIL)
  }

  return point.mul(tweak).toPublicKey(compressed)
}

/**
 * @param {Buffer[]} publicKeys
 * @param {boolean} compressed
 * @return {Buffer}
 */
exports.publicKeyCombine = function (publicKeys, compressed) {
  var points = new Array(publicKeys.length)
  for (var i = 0; i < publicKeys.length; ++i) {
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

/**
 * @param {Buffer} signature
 * @return {Buffer}
 */
exports.signatureNormalize = function (signature) {
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
 * @return {{r: Buffer, s: Buffer}}
 */
exports.signatureExport = function (signature) {
  var r = signature.slice(0, 32)
  var s = signature.slice(32, 64)
  if (new BN(r).cmp(ecparams.n) >= 0 || new BN(s).cmp(ecparams.n) >= 0) {
    throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL)
  }

  return {r: r, s: s}
}

/**
 * @param {{r: Buffer, s: Buffer}} sigObj
 * @return {Buffer}
 */
exports.signatureImport = function (sigObj) {
  var r = new BN(sigObj.r)
  if (r.cmp(ecparams.n) >= 0) {
    r = new BN(0)
  }

  var s = new BN(sigObj.s)
  if (s.cmp(ecparams.n) >= 0) {
    s = new BN(0)
  }

  var result = new Buffer(64)
  new Buffer(r.toArray(null, 32)).copy(result, 0)
  new Buffer(s.toArray(null, 32)).copy(result, 32)
  return result
}

/**
 * @param {Buffer} message
 * @param {Buffer} privateKey
 * @param {?sign~noncefn} noncefn
 * @param {?Buffer} data
 * @return {{signature: Buffer, recovery: number}}
 */
exports.sign = function (message, privateKey, noncefn, data) {
  if (noncefn === null) {
    noncefn = nonce_function_rfc6979
  }

  var d = new BN(privateKey)
  if (d.cmp(ecparams.n) >= 0 || d.cmpn(0) === 0) {
    throw new Error(messages.ECDSA_SIGN_FAIL)
  }

  var bnMessage = new BN(message)
  for (var count = 0; ; ++count) {
    var nonce = noncefn(message, privateKey, null, data, count)
    if (!Buffer.isBuffer(nonce) || nonce.length !== 32) {
      throw new Error(messages.ECDSA_SIGN_FAIL)
    }

    var k = new BN(nonce)
    if (k.cmp(ecparams.n) >= 0 || k.cmpn(0) === 0) {
      continue
    }

    var kp = g.mul(k)
    var r = kp.x.umod(ecparams.n)
    if (r.cmpn(0) === 0) {
      continue
    }

    var s = k.invm(ecparams.n).mul(r.mul(d).iadd(bnMessage)).umod(ecparams.n)
    if (s.cmpn(0) === 0) {
      continue
    }

    var recovery = (kp.x.cmp(r) !== 0 ? 2 : 0) | (kp.y.isOdd() ? 1 : 0)
    if (s.cmp(ecparams.nh) > 0) {
      s = ecparams.n.sub(s)
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
  var sigr = new BN(signature.slice(0, 32))
  var sigs = new BN(signature.slice(32, 64))
  if (sigr.cmp(ecparams.n) >= 0 || sigs.cmp(ecparams.n) >= 0) {
    throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL)
  }

  if (sigs.cmp(ecparams.nh) === 1 ||
      sigr.cmpn(0) === 0 || sigs.cmpn(0) === 0) {
    return false
  }

  var pub = ECPoint.fromPublicKey(publicKey)
  if (pub === null) {
    throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)
  }

  var sinv = sigs.invm(ecparams.n)
  var u1 = sinv.mul(new BN(message)).umod(ecparams.n)
  var u2 = sinv.mul(sigr).umod(ecparams.n)
  var point = g.mulAdd(u1, pub, u2)
  if (point.inf) {
    return false
  }

  return point.x.umod(ecparams.n).cmp(sigr) === 0
}

/**
 * @param {Buffer} message
 * @param {Buffer} signature
 * @param {number} recovery
 * @param {boolean} compressed
 * @return {Buffer}
 */
exports.recover = function (message, signature, recovery, compressed) {
  var sigr = new BN(signature.slice(0, 32))
  var sigs = new BN(signature.slice(32, 64))
  if (sigr.cmp(ecparams.n) >= 0 || sigs.cmp(ecparams.n) >= 0) {
    throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL)
  }

  do {
    if (sigr.cmpn(0) === 0 || sigs.cmpn(0) === 0) {
      break
    }

    var kpx = sigr
    if (recovery >> 1) {
      if (kpx.cmp(ecparams.p.umod(ecparams.n)) >= 0) {
        break
      }

      kpx = sigr.add(ecparams.n)
    }

    var kpPublicKey = new Buffer([0x02 + (recovery & 0x01)].concat(kpx.toArray(null, 32)))
    var kp = ECPoint.fromPublicKey(kpPublicKey)
    var eNeg = ecparams.n.sub(new BN(message))
    var rInv = sigr.invm(ecparams.n)
    return g.mulAdd(eNeg, kp, sigs).mul(rInv).toPublicKey(compressed)
  } while (false)

  throw new Error(messages.ECDSA_RECOVER_FAIL)
}

/**
 * @param {Buffer} publicKey
 * @param {Buffer} privateKey
 * @return {Buffer}
 */
exports.ecdh = function (publicKey, privateKey) {
}
