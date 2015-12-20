'use strict'

var expect = require('chai').expect

var util = require('./util')

/**
 * @param {Object} secp256k1
 * @param {Object} opts
 * @param {number} opts.repeat
 */
module.exports = function (secp256k1, opts) {
  describe.skip('ecdh', function () {
    it('public key should be a Buffer', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        secp256k1.ecdh(null, privateKey)
      }).to.throw(TypeError, 'public key should be a Buffer')
    })

    it('public key length is invalid', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed.slice(1)
        var privateKey = util.getPrivateKey()
        secp256k1.ecdh(publicKey, privateKey)
      }).to.throw(RangeError, 'public key length is invalid')
    })

    it('invalid public key', function () {
      expect(function () {
        var publicKey = util.getPublicKey()
        publicKey[0] = 0x01
        var privateKey = util.getPrivateKey()
        secp256k1.ecdh(publicKey, privateKey)
      }).to.throw(Error, 'the public key could not be parsed or is invalid')
    })

    it('secret key should be a Buffer', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed
        secp256k1.ecdh(publicKey, null)
      }).to.throw(TypeError, 'private key should be a Buffer')
    })

    it('secret key invalid length', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed
        var privateKey = util.getPrivateKey().slice(1)
        secp256k1.ecdh(publicKey, privateKey)
      }).to.throw(RangeError, 'private key length is invalid')
    })

    it('secret key equal N', function () {
      expect(function () {
        var publicKey = util.getPublicKey()
        var privateKey = new Buffer(util.ec.n.toArray(null, 32))
        secp256k1.ecdh(publicKey, privateKey)
      }).to.throw(Error, 'scalar was invalid (zero or overflow)')
    })

    util.repeatIt('random tests', opts.repeat, function () {
      var publicKey = util.getPublicKey().compressed
      var privateKey = util.getPrivateKey()

      var expected = util.ecdh(publicKey, privateKey)
      var result = secp256k1.ecdh(publicKey, privateKey)
      expect(result.toString('hex')).to.equal(expected.toString('hex'))
    })
  })
}
