var expect = require('chai').expect

var util = require('./util')

/**
 * @param {Object} secp256k1
 * @param {Object} opts
 * @param {number} opts.repeat
 */
module.exports = function (secp256k1, opts) {
  describe('sign', function () {
    it('message should be a Buffer', function () {
      expect(function () {
        secp256k1.sign(null, util.getPrivateKey())
      }).to.throw(TypeError, /message/)
    })

    it('secret key should be a Buffer', function () {
      expect(function () {
        secp256k1.sign(util.getMessage(), null)
      }).to.throw(TypeError, /secret/)
    })

    it('message invalid length', function () {
      expect(function () {
        secp256k1.sign(util.getMessage().slice(1), util.getPrivateKey())
      }).to.throw(RangeError, /message/)
    })

    it('secret key invalid length', function () {
      expect(function () {
        secp256k1.sign(util.getMessage(), util.getPrivateKey().slice(1))
      }).to.throw(RangeError, /secret/)
    })

    it('secret key is invalid', function () {
      expect(function () {
        secp256k1.sign(util.getMessage(), util.ecparams.n.toBuffer(32))
      }).to.throw(Error, /secret/)
    })
  })
}
