var expect = require('chai').expect

var util = require('./util')

/**
 * @param {Object} secp256k1
 * @param {Object} opts
 * @param {number} opts.repeat
 */
module.exports = function (secp256k1, opts) {
  describe('ecdh', function () {
    it('public key should be a Buffer', function () {
      expect(function () {
        secp256k1.ecdh(null, util.getPrivateKey())
      }).to.throw(TypeError, /public/)
    })

    it('secret key should be a Buffer', function () {
      expect(function () {
        secp256k1.ecdh(util.getPublicKey(), null)
      }).to.throw(TypeError, /secret/)
    })

    it('public key length is invalid', function () {
      expect(function () {
        secp256k1.ecdh(util.getPublicKey().slice(1), util.getPrivateKey())
      }).to.throw(RangeError, /public/)
    })

    it('secret key invalid length', function () {
      expect(function () {
        secp256k1.ecdh(util.getPublicKey(), util.getPrivateKey().slice(1))
      }).to.throw(RangeError, /secret/)
    })

    it('invalid public key', function () {
      expect(function () {
        var pubKey = util.getPublicKey()
        pubKey[0] = 0x01
        secp256k1.ecdh(pubKey, util.getPrivateKey())
      }).to.throw(Error, /public/)
    })

    it('secret key equal N', function () {
      expect(function () {
        secp256k1.ecdh(util.getPublicKey(), util.ecparams.n.toBuffer(32))
      }).to.throw(Error, /scalar/)
    })

    util.repeatIt('random tests', opts.repeat, function () {
      var pubKey = util.getPublicKey()
      var privKey = util.getPrivateKey()

      var expected = util.ecdh(pubKey, privKey)
      var result = secp256k1.ecdh(pubKey, privKey)
      expect(result.toString('hex')).to.equal(expected.toString('hex'))
    })
  })
}
