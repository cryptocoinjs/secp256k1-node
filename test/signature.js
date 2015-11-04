var expect = require('chai').expect
var BigInteger = require('bigi')

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
          util.ecparams.n.toBuffer(32),
          BigInteger.ONE.toBuffer(32)
        ])
        secp256k1.signatureNormalize(signature)
      }).to.throw(Error, /parse/)
    })

    it('normalize fail (s equal n/2)', function () {
      expect(function () {
        var signature = Buffer.concat([
          BigInteger.ONE.toBuffer(32),
          util.ecparams.nH.toBuffer(32)
        ])
        secp256k1.signatureNormalize(signature)
      }).to.throw(Error, /normalize/)
    })

    util.repeatIt('random tests', opts.repeat, function () {
      var msg = util.getMessage()
      var privKey = util.getPrivateKey()

      var sigObj = util.signSync(msg, privKey)
      if (sigObj.signatureLowS.toString('hex') === sigObj.signature.toString('hex')) {
        return expect(function () {
          secp256k1.signatureNormalize(sigObj.signature)
        }).to.throw(Error, /normalize/)
      }

      var result = secp256k1.signatureNormalize(sigObj.signature)
      expect(result.toString('hex')).to.equal(sigObj.signatureLowS.toString('hex'))
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
          util.ecparams.n.toBuffer(32),
          BigInteger.ONE.toBuffer(32)
        ])
        secp256k1.signatureExport(signature)
      }).to.throw(Error, /parse/)
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
  })

  describe('signatureExport/signatureImport', function () {
    util.repeatIt('random tests', opts.repeat, function () {
      var msg = util.getMessage()
      var privKey = util.getPrivateKey()

      var sig = util.signSync(msg, privKey).signatureLowS

      var der = secp256k1.signatureExport(sig)
      var result = secp256k1.signatureImport(der)
      expect(result.toString('hex')).to.equal(sig.toString('hex'))
    })
  })
}
