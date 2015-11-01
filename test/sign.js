var expect = require('chai').expect

var util = require('./util')

/**
 * @param {Object} secp256k1
 * @param {Object} opts
 * @param {number} opts.repeat
 */
module.exports = function (secp256k1, opts) {
  describe('sign', function () {
    it('return a Promise', function () {
      expect(secp256k1.sign()).to.be.instanceof(secp256k1.Promise)
    })

    it('callback should be a function', function () {
      expect(function () {
        secp256k1.sign(util.getMessage(), util.getPrivateKey(), null)
      }).to.throw(TypeError, /callback/)
    })

    it('message should be a Buffer', function () {
      var promise = secp256k1.sign(null, util.getPrivateKey())
      return expect(promise).to.be.rejectedWith(TypeError, /message/)
    })

    it('secret key should be a Buffer', function () {
      var promise = secp256k1.sign(util.getMessage(), null)
      return expect(promise).to.be.rejectedWith(TypeError, /secret/)
    })

    it('message invalid length', function () {
      var promise = secp256k1.sign(util.getMessage().slice(1), util.getPrivateKey())
      return expect(promise).to.be.rejectedWith(RangeError, /message/)
    })

    it('secret key invalid length', function () {
      var promise = secp256k1.sign(util.getMessage(), util.getPrivateKey().slice(1))
      return expect(promise).to.be.rejectedWith(RangeError, /secret/)
    })
  })

  describe('signSync', function () {
    it('message should be a Buffer', function () {
      expect(function () {
        secp256k1.signSync(null, util.getPrivateKey())
      }).to.throw(TypeError, /message/)
    })

    it('secret key should be a Buffer', function () {
      expect(function () {
        secp256k1.signSync(util.getMessage(), null)
      }).to.throw(TypeError, /secret/)
    })

    it('message invalid length', function () {
      expect(function () {
        secp256k1.signSync(util.getMessage().slice(1), util.getPrivateKey())
      }).to.throw(RangeError, /message/)
    })

    it('secret key invalid length', function () {
      expect(function () {
        secp256k1.signSync(util.getMessage(), util.getPrivateKey().slice(1))
      }).to.throw(RangeError, /secret/)
    })
  })
}

