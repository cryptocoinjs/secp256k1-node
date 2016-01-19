'use strict'

var messages = require('../messages.json')
var nonce_function_rfc6979 = require('./rfc6979')
var BN = require('./bn')
var ECPoint = require('./ecpoint')
var g = require('./ecpointg')

/**
 * @param {Buffer} privateKey
 * @return {boolean}
 */
exports.privateKeyVerify = function (privateKey) {
  var bn = BN.fromBuffer(privateKey)
  return !(bn.isOverflow() || bn.isZero())
}

/**
 * @param {Buffer} privateKey
 * @param {boolean} compressed
 * @return {Buffer}
 */
exports.privateKeyExport = function (privateKey, compressed) {
  var d = BN.fromBuffer(privateKey)
  if (d.isOverflow() || d.isZero()) {
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
  var bn = BN.fromBuffer(tweak)
  if (bn.isOverflow()) {
    throw new Error(messages.EC_PRIVATE_KEY_TWEAK_ADD_FAIL)
  }

  bn = bn.add(BN.fromBuffer(privateKey))
  if (bn.isOverflow()) {
    bn.isub(BN.n)
  }

  if (bn.isZero()) {
    throw new Error(messages.EC_PRIVATE_KEY_TWEAK_ADD_FAIL)
  }

  return bn.toBuffer()
}

/**
 * @param {Buffer} privateKey
 * @param {Buffer} tweak
 * @return {Buffer}
 */
exports.privateKeyTweakMul = function (privateKey, tweak) {
  var bn = BN.fromBuffer(tweak)
  if (bn.isOverflow() || bn.isZero()) {
    throw new Error(messages.EC_PRIVATE_KEY_TWEAK_MUL_FAIL)
  }

  bn = bn.umul(BN.fromBuffer(privateKey))
  if (bn.isOverflow()) {
    bn = bn.reduce()
  }

  return bn.toBuffer()
}

/**
 * @param {Buffer} privateKey
 * @param {boolean} compressed
 * @return {Buffer}
 */
exports.publicKeyCreate = function (privateKey, compressed) {
  var d = BN.fromBuffer(privateKey)
  if (d.isOverflow() || d.isZero()) {
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

  tweak = BN.fromBuffer(tweak)
  if (tweak.isOverflow()) {
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

  tweak = BN.fromBuffer(tweak)
  if (tweak.isOverflow() || tweak.isZero()) {
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
  var r = BN.fromBuffer(signature.slice(0, 32))
  var s = BN.fromBuffer(signature.slice(32, 64))
  if (r.isOverflow() || s.isOverflow()) {
    throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL)
  }

  var result = new Buffer(signature)
  if (s.isHigh()) {
    BN.n.sub(s).toBuffer().copy(result, 32)
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
  if (BN.fromBuffer(r).isOverflow() || BN.fromBuffer(s).isOverflow()) {
    throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL)
  }

  return {r: r, s: s}
}

/**
 * @param {{r: Buffer, s: Buffer}} sigObj
 * @return {Buffer}
 */
exports.signatureImport = function (sigObj) {
  var r = BN.fromBuffer(sigObj.r)
  if (r.isOverflow()) {
    r = BN.fromNumber(0)
  }

  var s = BN.fromBuffer(sigObj.s)
  if (s.isOverflow()) {
    s = BN.fromNumber(0)
  }

  var result = new Buffer(64)
  r.toBuffer().copy(result, 0)
  s.toBuffer().copy(result, 32)
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

  var d = BN.fromBuffer(privateKey)
  if (d.isOverflow() || d.isZero()) {
    throw new Error(messages.ECDSA_SIGN_FAIL)
  }

  var bnMessage = BN.fromBuffer(message)
  for (var count = 0; ; ++count) {
    var nonce = noncefn(message, privateKey, null, data, count)
    if (!Buffer.isBuffer(nonce) || nonce.length !== 32) {
      throw new Error(messages.ECDSA_SIGN_FAIL)
    }

    var k = BN.fromBuffer(nonce)
    if (k.isOverflow() || k.isZero()) {
      continue
    }

    var kp = g.mul(k)
    var r = kp.x.reduce()
    if (r.isZero()) {
      continue
    }

    var s = k.invm().iumul(r.umul(d).iadd(bnMessage).reduce()).reduce()
    if (s.isZero()) {
      continue
    }

    var recovery = (kp.x.ucmp(r) !== 0 ? 2 : 0) | (kp.y.isOdd() ? 1 : 0)
    if (s.isHigh()) {
      s = BN.n.sub(s)
      recovery ^= 1
    }

    return {
      signature: Buffer.concat([r.toBuffer(), s.toBuffer()]),
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
  var sigr = BN.fromBuffer(signature.slice(0, 32))
  var sigs = BN.fromBuffer(signature.slice(32, 64))
  if (sigr.isOverflow() || sigs.isOverflow()) {
    throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL)
  }

  if (sigs.isHigh() || sigr.isZero() || sigs.isZero()) {
    return false
  }

  var pub = ECPoint.fromPublicKey(publicKey)
  if (pub === null) {
    throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)
  }

  var sinv = sigs.invm()
  var u1 = sinv.umul(BN.fromBuffer(message)).reduce()
  var u2 = sinv.iumul(sigr).reduce()
  var point = g.mulAdd(u1, pub, u2)
  if (point.inf) {
    return false
  }

  return point.x.reduce().ucmp(sigr) === 0
}

/**
 * @param {Buffer} message
 * @param {Buffer} signature
 * @param {number} recovery
 * @param {boolean} compressed
 * @return {Buffer}
 */
exports.recover = function (message, signature, recovery, compressed) {
  var sigr = BN.fromBuffer(signature.slice(0, 32))
  var sigs = BN.fromBuffer(signature.slice(32, 64))
  if (sigr.isOverflow() || sigs.isOverflow()) {
    throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL)
  }

  do {
    if (sigr.isZero() || sigs.isZero()) {
      break
    }

    var kpx = sigr
    if (recovery >> 1) {
      if (kpx.ucmp(BN.psn) >= 0) {
        break
      }

      kpx = sigr.add(BN.n)
    }

    var kpPublicKey = Buffer.concat([new Buffer([0x02 + (recovery & 0x01)]), kpx.toBuffer()])
    var kp = ECPoint.fromPublicKey(kpPublicKey)
    var eNeg = BN.n.sub(BN.fromBuffer(message))
    var rInv = sigr.invm()
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
