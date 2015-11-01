var expect = require('chai').expect
var randomBytes = require('crypto').randomBytes
var BigInteger = require('bigi')

var SECP256K1_N = require('./const').SECP256K1_N
var SECP256K1_N_H = require('./const').SECP256K1_N_H
var util = require('./util')

/**
 * @param {Object} secp256k1
 * @param {Object} opts
 * @param {number} opts.repeat
 */
module.exports = function (secp256k1, opts) {
  describe('signatureNormalize', function () {
    it('signature should be a Buffer', function () {
      expect(function () {
        secp256k1.signatureNormalize(null)
      }).to.throw(TypeError)
    })

    it('invalid length', function () {
      expect(function () {
        secp256k1.signatureNormalize(util.getSignature().slice(1))
      }).to.throw(RangeError)
    })

    it('parse fail (r equal N)', function () {
      expect(function () {
        var signature = Buffer.concat([
          SECP256K1_N.toBuffer(32),
          randomBytes(32)
        ])
        secp256k1.signatureNormalize(signature)
      }).to.throw(Error, /parse/)
    })

    it('normalize fail (s is not high)', function () {
      expect(function () {
        var signature = Buffer.concat([
          randomBytes(32),
          SECP256K1_N_H.subtract(BigInteger.ONE).toBuffer(32)
        ])
        secp256k1.signatureNormalize(signature)
      }).to.throw(Error, /normalize/)
    })

    util.repeatIt.skip('random tests', function () {
    })
  })

  describe('signatureExport', function () {
    it('signature should be a Buffer', function () {
      expect(function () {
        secp256k1.signatureExport(null)
      }).to.throw(TypeError)
    })

    it('invalid length', function () {
      expect(function () {
        secp256k1.signatureExport(util.getSignature().slice(1))
      }).to.throw(RangeError)
    })

    it('parse fail (r equal N)', function () {
      expect(function () {
        var signature = Buffer.concat([
          SECP256K1_N.toBuffer(32),
          randomBytes(32)
        ])
        secp256k1.signatureExport(signature)
      }).to.throw(Error, /parse/)
    })

    util.repeatIt.skip('random tests', function () {
    })
  })

  describe('signatureImport', function () {
    it('signature should be a Buffer', function () {
      expect(function () {
        secp256k1.signatureImport(null)
      }).to.throw(TypeError)
    })

    it('parse fail', function () {
      expect(function () {
        secp256k1.signatureImport(new Buffer(0))
      }).to.throw(Error, /parse/)
    })

    util.repeatIt.skip('random tests', function () {
    })
  })
}
