var assert = require('assert')
var BigInteger = require('bigi')
var ecdsa = require('ecdsa')
var ecurve = require('ecurve')

var ecparams = ecurve.getCurveByName('secp256k1')
ecparams.nH = ecparams.n.shiftRight(1)

/**
 * @param {Buffer} message
 * @param {Buffer} privateKey
 * @return {{signature: string, recovery: number}}
 */
exports.sign = function (message, privateKey) {
  var D = BigInteger.fromBuffer(privateKey)
  var k = ecdsa.deterministicGenerateK(message, D)
  var Q = ecparams.G.multiply(k)
  var e = BigInteger.fromBuffer(message)

  var r = Q.affineX.mod(ecparams.n)
  assert.notEqual(r.signum(), 0, 'Invalid R value')

  var s = k.modInverse(ecparams.n).multiply(e.add(D.multiply(r))).mod(ecparams.n)
  assert.notEqual(s.signum(), 0, 'Invalid S value')

  if (s.compareTo(ecparams.nH) > 0) {
    s = ecparams.n.subtract(s)
  }

  return {
    signature: Buffer.concat([r.toBuffer(32), s.toBuffer(32)]),
    recovery: null // TODO
  }
}

/**
 * @param {Buffer} message
 * @param {Buffer} signature
 * @param {Buffer} publicKey
 * @return {boolean}
 */
exports.verify = function (message, signature, publicKey) {
  var e = BigInteger.fromBuffer(message)
  var r = BigInteger.fromBuffer(signature.slice(0, 32))
  var s = BigInteger.fromBuffer(signature.slice(32, 64))
  var Q = ecurve.Point.decodeFrom(ecparams, publicKey)

  if (r.signum() <= 0 ||
      r.compareTo(ecparams.n) >= 0 ||
      s.signum() <= 0 ||
      s.compareTo(ecparams.n) >= 0) {
    return false
  }

  var c = s.modInverse(ecparams.n)
  var u1 = e.multiply(c).mod(ecparams.n)
  var u2 = r.multiply(c).mod(ecparams.n)
  var R = ecparams.G.multiplyTwo(u1, Q, u2)
  var v = R.affineX.mod(ecparams.n)

  if (ecparams.isInfinity(R)) {
    return false
  }

  return v.equals(r)
}
