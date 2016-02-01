'use strict'

var BN = require('bn.js')
var EC = require('elliptic').ec

var messages = require('../messages.json')

var ec = new EC('secp256k1')
var ecparams = ec.curve

/**
 * @param {Buffer} publicKey
 * @return {?KeyPair}
 */
function pairFromPublicKey (publicKey) {
  var x
  var y

  var first = publicKey[0]
  if (publicKey.length === 33 && (first === 0x02 || first === 0x03)) {
    x = new BN(publicKey.slice(1, 33))

    // overflow
    if (x.cmp(ecparams.p) >= 0) {
      return null
    }

    x = x.toRed(ecparams.red)
    y = x.redSqr().redIMul(x).redIAdd(ecparams.b).redSqrt()
    if ((first === 0x03) !== y.isOdd()) {
      y = y.redNeg()
    }
  } else if (publicKey.length === 65 && (first === 0x04 || first === 0x06 || first === 0x07)) {
    x = new BN(publicKey.slice(1, 33))
    y = new BN(publicKey.slice(33, 65))

    // overflow
    if (x.cmp(ecparams.p) >= 0 || y.cmp(ecparams.p) >= 0) {
      return null
    }

    x = x.toRed(ecparams.red)
    y = y.toRed(ecparams.red)

    // is odd flag
    if ((first === 0x06 || first === 0x07) && y.isOdd() !== (first === 0x07)) {
      return null
    }

    // x*x*x + b = y*y
    var x3 = x.redSqr().redIMul(x)
    if (!y.redSqr().redISub(x3.redIAdd(ecparams.b)).isZero()) {
      return null
    }
  } else {
    return null
  }

  return ec.keyPair({pub: {x: x, y: y}})
}

/**
 * @param {Buffer} privateKey
 * @return {boolean}
 */
exports.privateKeyVerify = function (privateKey) {
  var bn = new BN(privateKey)
  return !(bn.cmp(ecparams.n) >= 0 || bn.isZero())
}

/**
 * @param {Buffer} privateKey
 * @param {boolean} compressed
 * @return {Buffer}
 */
exports.privateKeyExport = function (privateKey, compressed) {
  var d = new BN(privateKey)
  if (d.cmp(ecparams.n) >= 0 || d.isZero()) {
    throw new Error(messages.EC_PRIVATE_KEY_EXPORT_DER_FAIL)
  }

  return new Buffer(ec.keyFromPrivate(privateKey).getPublic(compressed, true))
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

  if (bn.isZero()) {
    throw new Error(messages.EC_PRIVATE_KEY_TWEAK_ADD_FAIL)
  }

  return bn.toArrayLike(Buffer, null, 32)
}

/**
 * @param {Buffer} privateKey
 * @param {Buffer} tweak
 * @return {Buffer}
 */
exports.privateKeyTweakMul = function (privateKey, tweak) {
  var bn = new BN(tweak)
  if (bn.cmp(ecparams.n) >= 0 || bn.isZero()) {
    throw new Error(messages.EC_PRIVATE_KEY_TWEAK_MUL_FAIL)
  }

  bn.imul(new BN(privateKey))
  if (bn.cmp(ecparams.n)) {
    bn = bn.umod(ecparams.n)
  }

  return bn.toArrayLike(Buffer, null, 32)
}

/**
 * @param {Buffer} privateKey
 * @param {boolean} compressed
 * @return {Buffer}
 */
exports.publicKeyCreate = function (privateKey, compressed) {
  var d = new BN(privateKey)
  if (d.cmp(ecparams.n) >= 0 || d.isZero()) {
    throw new Error(messages.EC_PUBLIC_KEY_CREATE_FAIL)
  }

  return new Buffer(ec.keyFromPrivate(privateKey).getPublic(compressed, true))
}

/**
 * @param {Buffer} publicKey
 * @param {boolean} compressed
 * @return {Buffer}
 */
exports.publicKeyConvert = function (publicKey, compressed) {
  var pair = pairFromPublicKey(publicKey)
  if (pair === null) {
    throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)
  }

  return new Buffer(pair.getPublic(compressed, true))
}

/**
 * @param {Buffer} publicKey
 * @return {boolean}
 */
exports.publicKeyVerify = function (publicKey) {
  return pairFromPublicKey(publicKey) !== null
}

/**
 * @param {Buffer} publicKey
 * @param {Buffer} tweak
 * @param {boolean} compressed
 * @return {Buffer}
 */
exports.publicKeyTweakAdd = function (publicKey, tweak, compressed) {
  var pair = pairFromPublicKey(publicKey)
  if (pair === null) {
    throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)
  }

  tweak = new BN(tweak)
  if (tweak.cmp(ecparams.n) >= 0) {
    throw new Error(messages.EC_PUBLIC_KEY_TWEAK_ADD_FAIL)
  }

  return new Buffer(ecparams.g.mul(tweak).add(pair.pub).encode(true, compressed))
}

/**
 * @param {Buffer} publicKey
 * @param {Buffer} tweak
 * @param {boolean} compressed
 * @return {Buffer}
 */
exports.publicKeyTweakMul = function (publicKey, tweak, compressed) {
  var pair = pairFromPublicKey(publicKey)
  if (pair === null) {
    throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)
  }

  tweak = new BN(tweak)
  if (tweak.cmp(ecparams.n) >= 0 || tweak.isZero()) {
    throw new Error(messages.EC_PUBLIC_KEY_TWEAK_MUL_FAIL)
  }

  return new Buffer(pair.pub.mul(tweak).encode(true, compressed))
}

/**
 * @param {Buffer[]} publicKeys
 * @param {boolean} compressed
 * @return {Buffer}
 */
exports.publicKeyCombine = function (publicKeys, compressed) {
  var pairs = new Array(publicKeys.length)
  for (var i = 0; i < publicKeys.length; ++i) {
    pairs[i] = pairFromPublicKey(publicKeys[i])
    if (pairs[i] === null) {
      throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)
    }
  }

  var point = pairs[0].pub
  for (var j = 1; j < pairs.length; ++j) {
    point = point.add(pairs[j].pub)
  }

  if (point.isInfinity()) {
    throw new Error(messages.EC_PUBLIC_KEY_COMBINE_FAIL)
  }

  return new Buffer(point.encode(true, compressed))
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
  if (s.cmp(ec.nh) === 1) {
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

  return new Buffer(r.toArray(null, 32).concat(s.toArray(null, 32)))
}

/**
 * @param {Buffer} message
 * @param {Buffer} privateKey
 * @param {?sign~noncefn} noncefn
 * @param {?Buffer} data
 * @return {{signature: Buffer, recovery: number}}
 */
exports.sign = function (message, privateKey, noncefn, data) {
  if (typeof noncefn === 'function') {
    var getNonce = noncefn
    noncefn = function (counter) {
      var nonce = getNonce(message, privateKey, null, data, counter)
      if (!Buffer.isBuffer(nonce) || nonce.length !== 32) {
        throw new Error(messages.ECDSA_SIGN_FAIL)
      }

      return new BN(nonce)
    }
  }

  var d = new BN(privateKey)
  if (d.cmp(ecparams.n) >= 0 || d.isZero()) {
    throw new Error(messages.ECDSA_SIGN_FAIL)
  }

  var result = ec.sign(message, privateKey, {canonical: true, k: noncefn, pers: data})
  return {
    signature: new Buffer(result.r.toArray(null, 32).concat(result.s.toArray(null, 32))),
    recovery: result.recoveryParam
  }
}

/**
 * @param {Buffer} message
 * @param {Buffer} signature
 * @param {Buffer} publicKey
 * @return {boolean}
 */
exports.verify = function (message, signature, publicKey) {
  var sigObj = {r: signature.slice(0, 32), s: signature.slice(32, 64)}

  var sigr = new BN(sigObj.r)
  var sigs = new BN(sigObj.s)
  if (sigr.cmp(ecparams.n) >= 0 || sigs.cmp(ecparams.n) >= 0) {
    throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL)
  }

  if (sigs.cmp(ec.nh) === 1 || sigr.isZero() || sigs.isZero()) {
    return false
  }

  var pair = pairFromPublicKey(publicKey)
  if (pair === null) {
    throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)
  }

  return ec.verify(message, sigObj, {x: pair.pub.x, y: pair.pub.y})
}

/**
 * @param {Buffer} message
 * @param {Buffer} signature
 * @param {number} recovery
 * @param {boolean} compressed
 * @return {Buffer}
 */
exports.recover = function (message, signature, recovery, compressed) {
  var sigObj = {r: signature.slice(0, 32), s: signature.slice(32, 64)}

  var sigr = new BN(sigObj.r)
  var sigs = new BN(sigObj.s)
  if (sigr.cmp(ecparams.n) >= 0 || sigs.cmp(ecparams.n) >= 0) {
    throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL)
  }

  try {
    if (sigr.isZero() || sigs.isZero()) {
      throw new Error()
    }

    var point = ec.recoverPubKey(message, sigObj, recovery)
    return new Buffer(point.encode(true, compressed))
  } catch (err) {
    throw new Error(messages.ECDSA_RECOVER_FAIL)
  }
}

/**
 * @param {Buffer} publicKey
 * @param {Buffer} privateKey
 * @return {Buffer}
 */
exports.ecdh = function (publicKey, privateKey) {
}
