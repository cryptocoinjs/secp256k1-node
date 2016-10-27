'use strict'
var createHash = require('create-hash')
var HmacDRBG = require('drbg.js/hmac')
var messages = require('../messages.json')
var BN = require('./bn')
var ECPoint = require('./ecpoint')
var g = require('./ecpointg')

var schnorrAlgo = new Buffer('Schnorr+SHA256  ', 'ascii')

exports.privateKeyVerify = function (privateKey) {
  var bn = BN.fromBuffer(privateKey)
  return !(bn.isOverflow() || bn.isZero())
}

exports.privateKeyExport = function (privateKey, compressed) {
  var d = BN.fromBuffer(privateKey)
  if (d.isOverflow() || d.isZero()) throw new Error(messages.EC_PRIVATE_KEY_EXPORT_DER_FAIL)

  return g.mul(d).toPublicKey(compressed)
}

exports.privateKeyTweakAdd = function (privateKey, tweak) {
  var bn = BN.fromBuffer(tweak)
  if (bn.isOverflow()) throw new Error(messages.EC_PRIVATE_KEY_TWEAK_ADD_FAIL)

  bn.iadd(BN.fromBuffer(privateKey))
  if (bn.isOverflow()) bn.isub(BN.n)
  if (bn.isZero()) throw new Error(messages.EC_PRIVATE_KEY_TWEAK_ADD_FAIL)

  return bn.toBuffer()
}

exports.privateKeyTweakMul = function (privateKey, tweak) {
  var bn = BN.fromBuffer(tweak)
  if (bn.isOverflow() || bn.isZero()) throw new Error(messages.EC_PRIVATE_KEY_TWEAK_MUL_FAIL)

  var d = BN.fromBuffer(privateKey)
  return bn.umul(d).ureduce().toBuffer()
}

exports.publicKeyCreate = function (privateKey, compressed) {
  var d = BN.fromBuffer(privateKey)
  if (d.isOverflow() || d.isZero()) throw new Error(messages.EC_PUBLIC_KEY_CREATE_FAIL)

  return g.mul(d).toPublicKey(compressed)
}

exports.publicKeyConvert = function (publicKey, compressed) {
  var point = ECPoint.fromPublicKey(publicKey)
  if (point === null) throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)

  return point.toPublicKey(compressed)
}

exports.publicKeyVerify = function (publicKey) {
  return ECPoint.fromPublicKey(publicKey) !== null
}

exports.publicKeyTweakAdd = function (publicKey, tweak, compressed) {
  var point = ECPoint.fromPublicKey(publicKey)
  if (point === null) throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)

  tweak = BN.fromBuffer(tweak)
  if (tweak.isOverflow()) throw new Error(messages.EC_PUBLIC_KEY_TWEAK_ADD_FAIL)

  return g.mul(tweak).add(point).toPublicKey(compressed)
}

exports.publicKeyTweakMul = function (publicKey, tweak, compressed) {
  var point = ECPoint.fromPublicKey(publicKey)
  if (point === null) throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)

  tweak = BN.fromBuffer(tweak)
  if (tweak.isOverflow() || tweak.isZero()) throw new Error(messages.EC_PUBLIC_KEY_TWEAK_MUL_FAIL)

  return point.mul(tweak).toPublicKey(compressed)
}

exports.publicKeyCombine = function (publicKeys, compressed) {
  var points = new Array(publicKeys.length)
  for (var i = 0; i < publicKeys.length; ++i) {
    points[i] = ECPoint.fromPublicKey(publicKeys[i])
    if (points[i] === null) throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)
  }

  var point = points[0]
  for (var j = 1; j < points.length; ++j) point = point.add(points[j])
  if (point.inf) throw new Error(messages.EC_PUBLIC_KEY_COMBINE_FAIL)

  return point.toPublicKey(compressed)
}

exports.signatureNormalize = function (signature) {
  var r = BN.fromBuffer(signature.slice(0, 32))
  var s = BN.fromBuffer(signature.slice(32, 64))
  if (r.isOverflow() || s.isOverflow()) throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL)

  var result = new Buffer(signature)
  if (s.isHigh()) BN.n.sub(s).toBuffer().copy(result, 32)

  return result
}

exports.signatureExport = function (signature) {
  var r = signature.slice(0, 32)
  var s = signature.slice(32, 64)
  if (BN.fromBuffer(r).isOverflow() || BN.fromBuffer(s).isOverflow()) throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL)

  return { r: r, s: s }
}

exports.signatureImport = function (sigObj) {
  var r = BN.fromBuffer(sigObj.r)
  if (r.isOverflow()) r = BN.fromNumber(0)

  var s = BN.fromBuffer(sigObj.s)
  if (s.isOverflow()) s = BN.fromNumber(0)

  return Buffer.concat([r.toBuffer(), s.toBuffer()])
}

exports.sign = function (message, privateKey, noncefn, data) {
  var d = BN.fromBuffer(privateKey)
  if (d.isOverflow() || d.isZero()) throw new Error(messages.ECDSA_SIGN_FAIL)

  if (noncefn === null) {
    var drbg = new HmacDRBG('sha256', privateKey, message, data)
    noncefn = function () { return drbg.generate(32) }
  }

  var bnMessage = BN.fromBuffer(message)
  for (var count = 0; ; ++count) {
    var nonce = noncefn(message, privateKey, null, data, count)
    if (!Buffer.isBuffer(nonce) || nonce.length !== 32) throw new Error(messages.ECDSA_SIGN_FAIL)

    var k = BN.fromBuffer(nonce)
    if (k.isOverflow() || k.isZero()) continue

    var kp = g.mul(k)
    var r = kp.x.fireduce()
    if (r.isZero()) continue

    var s = k.uinvm().umul(r.umul(d).ureduce().iadd(bnMessage).fireduce()).ureduce()
    if (s.isZero()) continue

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

exports.verify = function (message, signature, publicKey) {
  var sigr = BN.fromBuffer(signature.slice(0, 32))
  var sigs = BN.fromBuffer(signature.slice(32, 64))
  if (sigr.isOverflow() || sigs.isOverflow()) throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL)

  if (sigs.isHigh() || sigr.isZero() || sigs.isZero()) return false

  var pub = ECPoint.fromPublicKey(publicKey)
  if (pub === null) throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)

  var sinv = sigs.uinvm()
  var u1 = sinv.umul(BN.fromBuffer(message)).ureduce()
  var u2 = sinv.umul(sigr).ureduce()
  var point = g.mulAdd(u1, pub, u2)
  if (point.inf) return false

  // return ECPoint.fromECJPoint(point).x.fireduce().ucmp(sigr) === 0
  // Inversion-free
  var z2 = point.z.redSqr()
  if (sigr.redMul(z2).ucmp(point.x) === 0) return true
  if (sigr.ucmp(BN.psn) >= 0) return false

  return sigr.iadd(BN.psn).redMul(z2).ucmp(point.x) === 0
}

exports.recover = function (message, signature, recovery, compressed) {
  var sigr = BN.fromBuffer(signature.slice(0, 32))
  var sigs = BN.fromBuffer(signature.slice(32, 64))
  if (sigr.isOverflow() || sigs.isOverflow()) throw new Error(messages.ECDSA_SIGNATURE_PARSE_FAIL)

  do {
    if (sigr.isZero() || sigs.isZero()) break

    var kpx = sigr
    if (recovery >> 1) {
      if (kpx.ucmp(BN.psn) >= 0) break
      kpx = sigr.add(BN.n)
    }

    var kpPublicKey = Buffer.concat([new Buffer([0x02 + (recovery & 0x01)]), kpx.toBuffer()])
    var kp = ECPoint.fromPublicKey(kpPublicKey)
    if (kp === null) break

    var rInv = sigr.uinvm()
    var s1 = BN.n.sub(BN.fromBuffer(message)).umul(rInv).ureduce()
    var s2 = sigs.umul(rInv).ureduce()
    var point = ECPoint.fromECJPoint(g.mulAdd(s1, kp, s2))
    return point.toPublicKey(compressed)
  } while (false)

  throw new Error(messages.ECDSA_RECOVER_FAIL)
}

exports.ecdh = function (publicKey, privateKey) {
  var shared = exports.ecdhUnsafe(publicKey, privateKey, true)
  return createHash('sha256').update(shared).digest()
}

exports.ecdhUnsafe = function (publicKey, privateKey, compressed) {
  var point = ECPoint.fromPublicKey(publicKey)
  if (point === null) throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)

  var scalar = BN.fromBuffer(privateKey)
  if (scalar.isOverflow() || scalar.isZero()) throw new Error(messages.ECDH_FAIL)

  return point.mul(scalar).toPublicKey(compressed)
}

exports.schnorrSign = function (message, privateKey, noncefn, data) {
  var d = BN.fromBuffer(privateKey)
  if (d.isZero()) throw new Error(messages.SCHNORR_SIGN_FAIL)

  if (noncefn === null) {
    var drbg = new HmacDRBG('sha256', privateKey, message, data)
    noncefn = function () { return drbg.generate(32) }
  }

  for (var count = 0; ; ++count) {
    var nonce = noncefn(message, privateKey, schnorrAlgo, data, count)
    if (!Buffer.isBuffer(nonce) || nonce.length !== 32) throw new Error(messages.SCHNORR_SIGN_FAIL)

    var k = BN.fromBuffer(nonce)
    if (k.isOverflow() || k.isZero()) continue

    var rp = g.mul(k)
    var rx = rp.x.fireduce().toBuffer()
    var eb = createHash('sha256').updte(rx).update(message).digest()
    var e = BN.fromBuffer(eb)
    var s = k.isub(e.umul(d).ureduce()).fireduce()

    return Buffer.concat([ rx, s.toBuffer() ])
  }
}

exports.schnorrVerify = function (message, signature, publicKey) {
  var pub = ECPoint.fromPublicKey(publicKey)
  if (pub === null) throw new Error(messages.EC_PUBLIC_KEY_PARSE_FAIL)

  var eb = createHash('sha256').updte(signature.slice(0, 32)).update(message).digest()
  var e = BN.fromBuffer(eb)
  if (e.isOverflow() || e.isZero()) return false

  var s = BN.fromBuffer(signature.slice(32, 64))
  if (s.isOverflow()) return false

  var rp = g.mulAdd(s, pub, e)
  if (rp.y.isOdd()) return false

  var rx = BN.fromBuffer(signature.slice(0, 32))
  return rp.x.ucmp(rx) === 0
}

exports.schnorrRecover = function (message, signature, compressed) {
  var eb = createHash('sha256').updte(signature.slice(0, 32)).update(message).digest()
  var e = BN.fromBuffer(eb)
  if (e.isOverflow() || e.isZero()) throw new Error(messages.SCHNORR_RECOVER_FAIL)

  var s = BN.fromBuffer(signature.slice(32, 64))
  if (s.isOverflow()) throw new Error(messages.SCHNORR_RECOVER_FAIL)

  var rx = BN.fromBuffer(signature.slice(0, 32))
  var rp = ECPoint.fromX(rx, false)
  if (rp === null) throw new Error(messages.SCHNORR_RECOVER_FAIL)

  var einv = e.uinvm()
  var k1 = BN.n.sub(s).umul(einv).ureduce()
  var Q = ECPoint.fromECJPoint(g.mulAdd(k1, rp, einv))
  if (Q.inf) throw new Error(messages.SCHNORR_RECOVER_FAIL)

  return Q.toPublicKey(compressed)
}
