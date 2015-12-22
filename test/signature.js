'use strict'

var expect = require('chai').expect

var util = require('./util')
var messages = require('../lib/messages')

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
      }).to.throw(TypeError, messages.ECDSA_SIGNATURE_TYPE_INVALID)
    })

    it('invalid length', function () {
      expect(function () {
        var signature = util.getSignature().slice(1)
        secp256k1.signatureNormalize(signature)
      }).to.throw(RangeError, messages.ECDSA_SIGNATURE_LENGTH_INVALID)
    })

    it('parse fail (r equal N)', function () {
      expect(function () {
        var signature = Buffer.concat([
          new Buffer(util.ec.curve.n.toArray(null, 32)),
          new Buffer(util.BN_ONE.toArray(null, 32))
        ])
        secp256k1.signatureNormalize(signature)
      }).to.throw(Error, messages.ECDSA_SIGNATURE_PARSE_FAIL)
    })

    it('normalize return same signature (s equal n/2)', function () {
      var signature = Buffer.concat([
        new Buffer(util.BN_ONE.toArray(null, 32)),
        new Buffer(util.ec.nh.toArray(null, 32))
      ])
      var result = secp256k1.signatureNormalize(signature)
      expect(result.toString('hex')).to.equal(signature.toString('hex'))
    })

    util.repeatIt('random tests', opts.repeat, function () {
      var message = util.getMessage()
      var privateKey = util.getPrivateKey()

      var sigObj = util.sign(message, privateKey)
      var result = secp256k1.signatureNormalize(sigObj.signature)
      expect(result.toString('hex')).to.equal(sigObj.signatureLowS.toString('hex'))
    })
  })

  describe('signatureExport', function () {
    it('signature should be a Buffer', function () {
      expect(function () {
        secp256k1.signatureExport(null)
      }).to.throw(TypeError, messages.ECDSA_SIGNATURE_TYPE_INVALID)
    })

    it('invalid length', function () {
      expect(function () {
        var signature = util.getSignature().slice(1)
        secp256k1.signatureExport(signature)
      }).to.throw(RangeError, messages.ECDSA_SIGNATURE_LENGTH_INVALID)
    })

    it('parse fail (r equal N)', function () {
      expect(function () {
        var signature = Buffer.concat([
          new Buffer(util.ec.n.toArray(null, 32)),
          new Buffer(util.BN_ONE.toArray(null, 32))
        ])
        secp256k1.signatureExport(signature)
      }).to.throw(Error, messages.ECDSA_SIGNATURE_PARSE_FAIL)
    })
  })

  describe('signatureImport', function () {
    it('signature should be a Buffer', function () {
      expect(function () {
        secp256k1.signatureImport(null)
      }).to.throw(TypeError, messages.ECDSA_SIGNATURE_TYPE_INVALID)
    })

    it('parse fail', function () {
      expect(function () {
        secp256k1.signatureImport(new Buffer(1))
      }).to.throw(Error, messages.ECDSA_SIGNATURE_PARSE_DER_FAIL)
    })
  })

  describe('signatureExport/signatureImport', function () {
    util.repeatIt('random tests', opts.repeat, function () {
      var message = util.getMessage()
      var privateKey = util.getPrivateKey()

      var signature = util.sign(message, privateKey).signatureLowS

      var der = secp256k1.signatureExport(signature)
      var result = secp256k1.signatureImport(der)
      expect(result.toString('hex')).to.equal(signature.toString('hex'))
    })
  })
}
