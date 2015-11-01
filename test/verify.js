var expect = require('chai').expect
var randomBytes = require('crypto').randomBytes

var SECP256K1_N = require('./const').SECP256K1_N
var util = require('./util')

/**
 * @param {Object} secp256k1
 * @param {Object} opts
 * @param {number} opts.repeat
 */
module.exports = function (secp256k1, opts) {
  describe('verify', function () {
    it('return a Promise', function () {
      expect(secp256k1.verify()).to.be.instanceof(secp256k1.Promise)
    })

    it('callback should be a function', function () {
      expect(function () {
        secp256k1.verify(util.getMessage(), util.getSignature(), util.getPublicKey(), null)
      }).to.throw(TypeError, /callback/)
    })

    it('message should be a Buffer', function () {
      var promise = secp256k1.verify(null, util.getSignature(), util.getPublicKey())
      return expect(promise).to.be.rejectedWith(TypeError, /message/)
    })

    it('signature should be a Buffer', function () {
      var promise = secp256k1.verify(util.getMessage(), null, util.getPublicKey())
      return expect(promise).to.be.rejectedWith(TypeError, /signature/)
    })

    it('public key should be a Buffer', function () {
      var promise = secp256k1.verify(util.getMessage(), util.getSignature(), null)
      return expect(promise).to.be.rejectedWith(TypeError, /public/)
    })

    it('message length is invalid', function () {
      var promise = secp256k1.verify(util.getMessage().slice(1), util.getSignature(), util.getPublicKey())
      return expect(promise).to.be.rejectedWith(RangeError, /message/)
    })

    it('signature length is invalid', function () {
      var promise = secp256k1.verify(util.getMessage(), util.getSignature().slice(1), util.getPublicKey())
      return expect(promise).to.be.rejectedWith(RangeError, /signature/)
    })

    it('public key length is invalid', function () {
      var promise = secp256k1.verify(util.getMessage(), util.getSignature(), util.getPublicKey().slice(1))
      return expect(promise).to.be.rejectedWith(RangeError, /public/)
    })

    it('public key is invalid (version is 0x01)', function () {
      var pubKey = util.getPublicKey()
      pubKey[0] = 0x01
      var promise = secp256k1.verify(util.getMessage(), util.getSignature(), pubKey)
      return expect(promise).to.be.rejectedWith(Error, /public/)
    })

    it('signature is invalid (r equal N)', function () {
      var signature = Buffer.concat([
        SECP256K1_N.toBuffer(32),
        randomBytes(32)
      ])
      var promise = secp256k1.verify(util.getMessage(), signature, util.getPublicKey())
      return expect(promise).to.be.rejectedWith(Error, /signature/)
    })
  })

  describe('verifySync', function () {
    it('message should be a Buffer', function () {
      expect(function () {
        secp256k1.verifySync(null, util.getSignature(), util.getPublicKey())
      }).to.throw(TypeError, /message/)
    })

    it('signature should be a Buffer', function () {
      expect(function () {
        secp256k1.verifySync(util.getMessage(), null, util.getPublicKey())
      }).to.throw(TypeError, /signature/)
    })

    it('public key should be a Buffer', function () {
      expect(function () {
        secp256k1.verifySync(util.getMessage(), util.getSignature(), null)
      }).to.throw(TypeError, /public/)
    })

    it('message length is invalid', function () {
      expect(function () {
        secp256k1.verifySync(util.getMessage().slice(1), util.getSignature(), util.getPublicKey())
      }).to.throw(RangeError, /message/)
    })

    it('signature length is invalid', function () {
      expect(function () {
        secp256k1.verifySync(util.getMessage(), util.getSignature().slice(1), util.getPublicKey())
      }).to.throw(RangeError, /signature/)
    })

    it('public key length is invalid', function () {
      expect(function () {
        secp256k1.verifySync(util.getMessage(), util.getSignature(), util.getPublicKey().slice(1))
      }).to.throw(RangeError, /public/)
    })

    it('public key is invalid (version is 0x01)', function () {
      expect(function () {
        var pubKey = util.getPublicKey()
        pubKey[0] = 0x01
        secp256k1.verifySync(util.getMessage(), util.getSignature(), pubKey)
      }).to.throw(Error, /public/)
    })

    it('signature is invalid (r equal N)', function () {
      expect(function () {
        var signature = Buffer.concat([
          SECP256K1_N.toBuffer(32),
          randomBytes(32)
        ])
        secp256k1.verifySync(util.getMessage(), signature, util.getPublicKey())
      }).to.throw(Error, /signature/)
    })
  })
}

