var expect = require('chai').expect

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
      }).to.throw(TypeError, 'signature should be a Buffer')
    })

    it('invalid length', function () {
      expect(function () {
        var signature = util.getSignature().slice(1)
        secp256k1.signatureNormalize(signature)
      }).to.throw(RangeError, 'signature length is invalid')
    })

    it('parse fail (r equal N)', function () {
      expect(function () {
        var signature = Buffer.concat([
          new Buffer(util.ec.curve.n.toArray(null, 32)),
          new Buffer(util.BN_ONE.toArray(null, 32))
        ])
        secp256k1.signatureNormalize(signature)
      }).to.throw(Error, 'couldn\'t parse signature')
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
      var msg = util.getMessage()
      var privateKey = util.getPrivateKey()

      var sigObj = util.sign(msg, privateKey)
      var result = secp256k1.signatureNormalize(sigObj.signature)
      expect(result.toString('hex')).to.equal(sigObj.signatureLowS.toString('hex'))
    })
  })

  describe('signatureExport', function () {
    it('signature should be a Buffer', function () {
      expect(function () {
        secp256k1.signatureExport(null)
      }).to.throw(TypeError, 'signature should be a Buffer')
    })

    it('invalid length', function () {
      expect(function () {
        var signature = util.getSignature().slice(1)
        secp256k1.signatureExport(signature)
      }).to.throw(RangeError, 'signature length is invalid')
    })

    it('parse fail (r equal N)', function () {
      expect(function () {
        var signature = Buffer.concat([
          new Buffer(util.ec.n.toArray(null, 32)),
          new Buffer(util.BN_ONE.toArray(null, 32))
        ])
        secp256k1.signatureExport(signature)
      }).to.throw(Error, 'couldn\'t parse signature')
    })
  })

  describe('signatureImport', function () {
    it('signature should be a Buffer', function () {
      expect(function () {
        secp256k1.signatureImport(null)
      }).to.throw(TypeError, 'signature should be a Buffer')
    })

    it('parse fail', function () {
      expect(function () {
        secp256k1.signatureImport(new Buffer(1))
      }).to.throw(Error, 'couldn\'t parse DER signature')
    })
  })

  describe('signatureExport/signatureImport', function () {
    util.repeatIt('random tests', opts.repeat, function () {
      var msg = util.getMessage()
      var privKey = util.getPrivateKey()

      var signature = util.sign(msg, privKey).signatureLowS

      var der = secp256k1.signatureExport(signature)
      var result = secp256k1.signatureImport(der)
      expect(result.toString('hex')).to.equal(signature.toString('hex'))
    })
  })
}
