const assert = require('assert').strict
const BigInteger = require('bigi')
const ecdsa = require('ecdsa')
const ecurve = require('ecurve')
const ECKey = require('eckey')

const ecparams = ecurve.getCurveByName('secp256k1')
ecparams.nH = ecparams.n.shiftRight(1)

function publicKeyCreate (privateKey) {
  const eckey = new ECKey(privateKey)
  return eckey.publicKey
}

function alwaysTrue () { return true }

function ecdsaSign (message, privateKey) {
  const D = BigInteger.fromBuffer(privateKey)
  const k = ecdsa.deterministicGenerateK(message, privateKey, alwaysTrue)
  const Q = ecparams.G.multiply(k)
  const e = BigInteger.fromBuffer(message)

  const r = Q.affineX.mod(ecparams.n)
  assert.notEqual(r.signum(), 0, 'Invalid R value')

  let s = k.modInverse(ecparams.n).multiply(e.add(D.multiply(r))).mod(ecparams.n)
  assert.notEqual(s.signum(), 0, 'Invalid S value')
  if (s.compareTo(ecparams.nH) > 0) s = ecparams.n.subtract(s)

  return {
    signature: Buffer.concat([r.toBuffer(32), s.toBuffer(32)]),
    recid: null // TODO
  }
}

function ecdsaVerify (message, signature, publicKey) {
  const e = BigInteger.fromBuffer(message)
  const r = BigInteger.fromBuffer(signature.slice(0, 32))
  const s = BigInteger.fromBuffer(signature.slice(32, 64))
  const Q = ecurve.Point.decodeFrom(ecparams, publicKey)

  if (r.signum() <= 0 || r.compareTo(ecparams.n) >= 0 ||
      s.signum() <= 0 || s.compareTo(ecparams.n) >= 0) return false

  const c = s.modInverse(ecparams.n)
  const u1 = e.multiply(c).mod(ecparams.n)
  const u2 = r.multiply(c).mod(ecparams.n)
  const R = ecparams.G.multiplyTwo(u1, Q, u2)
  if (ecparams.isInfinity(R)) return false

  return R.affineX.mod(ecparams.n).equals(r)
}

module.exports = {
  publicKeyCreate,
  ecdsaSign,
  ecdsaVerify
}
