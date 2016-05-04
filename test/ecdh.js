'use strict'
var messages = require('../lib/messages')

var util = require('./util')

module.exports = function (t, secp256k1) {
  function commonTests (t, ecdh) {
    t.test('public key should be a Buffer', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = null
        ecdh(publicKey, privateKey)
      }, new RegExp('^TypeError: ' + messages.EC_PUBLIC_KEY_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('public key length is invalid', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        ecdh(publicKey, privateKey)
      }, new RegExp('^RangeError: ' + messages.EC_PUBLIC_KEY_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('invalid public key', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        publicKey[0] = 0x00
        ecdh(publicKey, privateKey)
      }, new RegExp('^Error: ' + messages.EC_PUBLIC_KEY_PARSE_FAIL + '$'))
      t.end()
    })

    t.test('secret key should be a Buffer', function (t) {
      t.throws(function () {
        var privateKey = null
        var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        ecdh(publicKey, privateKey)
      }, new RegExp('^TypeError: ' + messages.EC_PRIVATE_KEY_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('secret key invalid length', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey().slice(1)
        var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        ecdh(publicKey, privateKey)
      }, new RegExp('^RangeError: ' + messages.EC_PRIVATE_KEY_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('secret key equal zero', function (t) {
      t.throws(function () {
        var privateKey = util.ec.curve.zero.fromRed().toArrayLike(Buffer, 'be', 32)
        var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        ecdh(publicKey, privateKey)
      }, new RegExp('^Error: scalar was invalid \\(zero or overflow\\)$'))
      t.end()
    })

    t.test('secret key equal N', function (t) {
      t.throws(function () {
        var privateKey = util.ec.n.toArrayLike(Buffer, 'be', 32)
        var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        ecdh(publicKey, privateKey)
      }, new RegExp('^Error: scalar was invalid \\(zero or overflow\\)$'))
      t.end()
    })
  }

  t.test('ecdh', function (t) {
    commonTests(t, secp256k1.ecdh)

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var privateKey1 = util.getPrivateKey()
      var publicKey1 = util.getPublicKey(privateKey1).compressed
      var privateKey2 = util.getPrivateKey()
      var publicKey2 = util.getPublicKey(privateKey2).compressed

      var shared1 = secp256k1.ecdh(publicKey1, privateKey2)
      var shared2 = secp256k1.ecdh(publicKey2, privateKey1)
      t.same(shared1, shared2)

      t.end()
    })

    t.end()
  })

  t.test('ecdhUnsafe', function (t) {
    commonTests(t, secp256k1.ecdhUnsafe)

    t.test('compressed should be a boolean', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.ecdhUnsafe(publicKey, privateKey, null)
      }, new RegExp('^TypeError: ' + messages.COMPRESSED_TYPE_INVALID + '$'))
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var privateKey1 = util.getPrivateKey()
      var publicKey1 = util.getPublicKey(privateKey1).compressed
      var privateKey2 = util.getPrivateKey()
      var publicKey2 = util.getPublicKey(privateKey2).compressed

      var shared1c = secp256k1.ecdhUnsafe(publicKey1, privateKey2, true)
      var shared2c = secp256k1.ecdhUnsafe(publicKey2, privateKey1, true)
      t.same(shared1c, shared2c)

      var shared1un = secp256k1.ecdhUnsafe(publicKey1, privateKey2, false)
      var shared2un = secp256k1.ecdhUnsafe(publicKey2, privateKey1, false)
      t.same(shared1un, shared2un)

      t.end()
    })

    t.end()
  })
}
