'use strict'
var assert = require('assert').strict
var BigInteger = require('bigi')
var ecdsa = require('ecdsa')
var ecurve = require('ecurve')
var ECKey = require('eckey')

var ecparams = ecurve.getCurveByName('secp256k1')
ecparams.nH = ecparams.n.shiftRight(1)

function publicKeyCreate (privateKey) {
  var eckey = new ECKey(privateKey)
  return eckey.publicKey
}

function alwaysTrue () { return true }

function sign (message, privateKey) {
  var D = BigInteger.fromBuffer(privateKey)
  var k = ecdsa.deterministicGenerateK(message, privateKey, alwaysTrue)
  var Q = ecparams.G.multiply(k)
  var e = BigInteger.fromBuffer(message)

  var r = Q.affineX.mod(ecparams.n)
  assert.notEqual(r.signum(), 0, 'Invalid R value')

  var s = k.modInverse(ecparams.n).multiply(e.add(D.multiply(r))).mod(ecparams.n)
  assert.notEqual(s.signum(), 0, 'Invalid S value')
  if (s.compareTo(ecparams.nH) > 0) s = ecparams.n.subtract(s)

  return {
    signature: Buffer.concat([r.toBuffer(32), s.toBuffer(32)]),
    recovery: null // TODO
  }
}

function verify (message, signature, publicKey) {
  var e = BigInteger.fromBuffer(message)
  var r = BigInteger.fromBuffer(signature.slice(0, 32))
  var s = BigInteger.fromBuffer(signature.slice(32, 64))
  var Q = ecurve.Point.decodeFrom(ecparams, publicKey)

  if (r.signum() <= 0 || r.compareTo(ecparams.n) >= 0 ||
      s.signum() <= 0 || s.compareTo(ecparams.n) >= 0) return false

  var c = s.modInverse(ecparams.n)
  var u1 = e.multiply(c).mod(ecparams.n)
  var u2 = r.multiply(c).mod(ecparams.n)
  var R = ecparams.G.multiplyTwo(u1, Q, u2)
  if (ecparams.isInfinity(R)) return false

  return R.affineX.mod(ecparams.n).equals(r)
}

module.exports = {
  publicKeyCreate: publicKeyCreate,
  sign: sign,
  verify: verify
}
