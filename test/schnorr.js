'use strict'
var getRandomBytes = require('crypto').randomBytes
var messages = require('../lib/messages')

var util = require('./util')

module.exports = function (t, secp256k1) {
  t.test('schnorrSign', function (t) {
    t.test('message should be a Buffer', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        secp256k1.schnorrSign(null, privateKey)
      }, new RegExp('^TypeError: ' + messages.MSG32_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('message invalid length', function (t) {
      t.throws(function () {
        var message = util.getMessage().slice(1)
        var privateKey = util.getPrivateKey()
        secp256k1.schnorrSign(message, privateKey)
      }, new RegExp('^RangeError: ' + messages.MSG32_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('private key should be a Buffer', function (t) {
      t.throws(function () {
        var message = util.getMessage()
        secp256k1.schnorrSign(message, null)
      }, new RegExp('^TypeError: ' + messages.EC_PRIVATE_KEY_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('private key invalid length', function (t) {
      t.throws(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey().slice(1)
        secp256k1.schnorrSign(message, privateKey)
      }, new RegExp('^RangeError: ' + messages.EC_PRIVATE_KEY_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('options should be an Object', function (t) {
      t.throws(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey()
        secp256k1.schnorrSign(message, privateKey, null)
      }, new RegExp('^TypeError: ' + messages.OPTIONS_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('options.data should be a Buffer', function (t) {
      t.throws(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey()
        secp256k1.schnorrSign(message, privateKey, { data: null })
      }, new RegExp('^TypeError: ' + messages.OPTIONS_DATA_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('options.data length is invalid', function (t) {
      t.throws(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey()
        var data = getRandomBytes(31)
        secp256k1.schnorrSign(message, privateKey, { data: data })
      }, new RegExp('^RangeError: ' + messages.OPTIONS_DATA_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('options.noncefn should be a Function', function (t) {
      t.throws(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey()
        secp256k1.schnorrSign(message, privateKey, { noncefn: null })
      }, new RegExp('^TypeError: ' + messages.OPTIONS_NONCEFN_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('noncefn return not a Buffer', function (t) {
      t.throws(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey()
        var noncefn = function () { return null }
        secp256k1.schnorrSign(message, privateKey, { noncefn: noncefn })
      }, new RegExp('^Error: ' + messages.ECDSA_SIGN_FAIL + '$'))
      t.end()
    })

    t.test('noncefn return Buffer with invalid length', function (t) {
      t.throws(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey()
        var noncefn = function () { return getRandomBytes(31) }
        secp256k1.schnorrSign(message, privateKey, { noncefn: noncefn })
      }, new RegExp('^Error: ' + messages.ECDSA_SIGN_FAIL + '$'))
      t.end()
    })

    t.test('check options.noncefn arguments', function (t) {
      t.plan(5)
      var message = util.getMessage()
      var privateKey = util.getPrivateKey()
      var data = getRandomBytes(32)
      var noncefn = function (message2, privateKey2, algo, data2, attempt) {
        t.same(message2, message)
        t.same(privateKey, privateKey)
        t.same(algo, Buffer.from('Schnorr+SHA256  ', 'ascii'))
        t.same(data2, data)
        t.same(attempt, 0)
        return getRandomBytes(32)
      }
      secp256k1.schnorrSign(message, privateKey, { data: data, noncefn: noncefn })
      t.end()
    })

    t.end()
  })

  t.test('schnorrVerify', function (t) {
    t.test('message should be a Buffer', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(message, privateKey)
        var publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.schnorrVerify(null, signature, publicKey)
      }, new RegExp('^TypeError: ' + messages.MSG32_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('message length is invalid', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage().slice(1)
        var signature = util.getSignature(message, privateKey)
        var publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.schnorrVerify(message, signature, publicKey)
      }, new RegExp('^RangeError: ' + messages.MSG32_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('signature should be a Buffer', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.schnorrVerify(message, null, publicKey)
      }, new RegExp('^TypeError: ' + messages.ECDSA_SIGNATURE_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('signature length is invalid', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(message, privateKey).slice(1)
        var publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.schnorrVerify(message, signature, publicKey)
      }, new RegExp('^RangeError: ' + messages.ECDSA_SIGNATURE_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('signature is invalid (r equal N)', function (t) {
      var privateKey = util.getPrivateKey()
      var message = util.getMessage()
      var signature = Buffer.concat([
        util.ec.curve.n.toArrayLike(Buffer, 'be', 32),
        getRandomBytes(32)
      ])
      var publicKey = util.getPublicKey(privateKey).compressed
      t.false(secp256k1.schnorrVerify(message, signature, publicKey))
      t.end()
    })

    t.test('public key should be a Buffer', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(message, privateKey)
        secp256k1.schnorrVerify(message, signature, null)
      }, new RegExp('^TypeError: ' + messages.EC_PUBLIC_KEY_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('public key length is invalid', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(message, privateKey)
        var publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        secp256k1.schnorrVerify(message, signature, publicKey)
      }, new RegExp('^RangeError: ' + messages.EC_PUBLIC_KEY_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('public key is invalid (version is 0x01)', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(message, privateKey)
        var publicKey = util.getPublicKey(privateKey).compressed
        publicKey[0] = 0x01
        secp256k1.schnorrVerify(message, signature, publicKey)
      }, new RegExp('^Error: ' + messages.EC_PUBLIC_KEY_PARSE_FAIL + '$'))
      t.end()
    })

    t.end()
  })

  t.test('schnorrRecover', function (t) {
    t.end()
  })

  t.test('schnorrGenerateNoncePair', function (t) {
    t.end()
  })

  t.test('schnorrPartialSign', function (t) {
    t.end()
  })

  t.test('schnorrPartialCombine', function (t) {
    t.end()
  })
}
