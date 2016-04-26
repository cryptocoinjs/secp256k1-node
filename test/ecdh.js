'use strict'
/* global describe, it */

var expect = require('chai').expect

var util = require('./util')
var messages = require('../lib/messages')

module.exports = function (secp256k1, opts) {
  describe.skip('ecdh', function () {
    it('public key should be a Buffer', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        secp256k1.ecdh(null, privateKey)
      }).to.throw(TypeError, messages.EC_PUBLIC_KEY_TYPE_INVALID)
    })

    it('public key length is invalid', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed.slice(1)
        var privateKey = util.getPrivateKey()
        secp256k1.ecdh(publicKey, privateKey)
      }).to.throw(RangeError, messages.EC_PUBLIC_KEY_LENGTH_INVALID)
    })

    it('invalid public key', function () {
      expect(function () {
        var publicKey = util.getPublicKey()
        publicKey[0] = 0x01
        var privateKey = util.getPrivateKey()
        secp256k1.ecdh(publicKey, privateKey)
      }).to.throw(Error, messages.EC_PUBLIC_KEY_PARSE_FAIL)
    })

    it('secret key should be a Buffer', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed
        secp256k1.ecdh(publicKey, null)
      }).to.throw(TypeError, messages.EC_PRIVATE_KEY_TYPE_INVALID)
    })

    it('secret key invalid length', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed
        var privateKey = util.getPrivateKey().slice(1)
        secp256k1.ecdh(publicKey, privateKey)
      }).to.throw(RangeError, messages.EC_PRIVATE_KEY_LENGTH_INVALID)
    })

    it('secret key equal N', function () {
      expect(function () {
        var publicKey = util.getPublicKey()
        var privateKey = new Buffer(util.ec.n.toArray(null, 32))
        secp256k1.ecdh(publicKey, privateKey)
      }).to.throw(Error, messages.ECDH_FAIL)
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
