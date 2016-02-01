'use strict'

var expect = require('chai').expect
var BigNum = require('bignum')

exports.BN_MAX256 = BigNum.pow(2, 256).sub(1)
exports.N = BigNum.fromBuffer(new Buffer('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 'hex'))
exports.NH = exports.N.shiftRight(1)
exports.P = BigNum.fromBuffer(new Buffer('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 'hex'))

/**
 * @param {Buffer} buffer
 * @return {Buffer}
 */
exports.fillZeros = function (buffer) {
  if (buffer.length >= 32) {
    return buffer.slice(-32)
  }

  var zbuf = new Buffer(32 - buffer.length)
  zbuf.fill(0)
  return Buffer.concat([zbuf, buffer])
}

/**
 * @param {BN} bn
 * @param {BigNum} bignum
 */
exports.testBN = function (bn, bignum) {
  var isNeg = bignum.cmp(0) < 0
  if (isNeg) {
    bignum = bignum.neg()
  }

  try {
    expect(bn.negative).to.equal(isNeg ? 1 : 0)
    expect(bn.length).to.equal(Math.max(Math.ceil(bignum.bitLength() / 26), 1))
    for (var i = 0, bign = bignum; i < bn.length; ++i) {
      expect(bn.words[i]).to.equal(bign.and(0x03ffffff).toNumber())
      bign = bign.shiftRight(26)
    }
  } catch (err) {
    console.log(bn)
    console.log(bn.toBuffer().toString('hex'))
    console.log(exports.fillZeros(bignum.toBuffer()).toString('hex'), isNeg)
    throw err
  }
}
