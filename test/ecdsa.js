'use strict'
var getRandomBytes = require('crypto').randomBytes
var messages = require('../lib/messages')

var util = require('./util')

module.exports = function (t, secp256k1) {
  t.test('sign', function (t) {
    t.test('message should be a Buffer', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        secp256k1.sign(null, privateKey)
      }, new RegExp('^TypeError: ' + messages.MSG32_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('message invalid length', function (t) {
      t.throws(function () {
        var message = util.getMessage().slice(1)
        var privateKey = util.getPrivateKey()
        secp256k1.sign(message, privateKey)
      }, new RegExp('^RangeError: ' + messages.MSG32_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('private key should be a Buffer', function (t) {
      t.throws(function () {
        var message = util.getMessage()
        secp256k1.sign(message, null)
      }, new RegExp('^TypeError: ' + messages.EC_PRIVATE_KEY_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('private key invalid length', function (t) {
      t.throws(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey().slice(1)
        secp256k1.sign(message, privateKey)
      }, new RegExp('^RangeError: ' + messages.EC_PRIVATE_KEY_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('private key is invalid', function (t) {
      t.throws(function () {
        var message = util.getMessage()
        var privateKey = new Buffer(util.ec.n.toArray(null, 32))
        secp256k1.sign(message, privateKey)
      }, new RegExp('^Error: ' + messages.ECDSA_SIGN_FAIL + '$'))
      t.end()
    })

    t.test('options should be an Object', function (t) {
      t.throws(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey()
        secp256k1.sign(message, privateKey, null)
      }, new RegExp('^TypeError: ' + messages.OPTIONS_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('options.data should be a Buffer', function (t) {
      t.throws(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey()
        secp256k1.sign(message, privateKey, { data: null })
      }, new RegExp('^TypeError: ' + messages.OPTIONS_DATA_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('options.data length is invalid', function (t) {
      t.throws(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey()
        var data = getRandomBytes(31)
        secp256k1.sign(message, privateKey, { data: data })
      }, new RegExp('^RangeError: ' + messages.OPTIONS_DATA_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('options.noncefn should be a Function', function (t) {
      t.throws(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey()
        secp256k1.sign(message, privateKey, { noncefn: null })
      }, new RegExp('^TypeError: ' + messages.OPTIONS_NONCEFN_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('noncefn return not a Buffer', function (t) {
      t.throws(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey()
        var noncefn = function () { return null }
        secp256k1.sign(message, privateKey, { noncefn: noncefn })
      }, new RegExp('^Error: ' + messages.ECDSA_SIGN_FAIL + '$'))
      t.end()
    })

    t.test('noncefn return Buffer with invalid length', function (t) {
      t.throws(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey()
        var noncefn = function () { return getRandomBytes(31) }
        secp256k1.sign(message, privateKey, { noncefn: noncefn })
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
        t.same(algo, null)
        t.same(data2, data)
        t.same(attempt, 0)
        return getRandomBytes(32)
      }
      secp256k1.sign(message, privateKey, { data: data, noncefn: noncefn })
      t.end()
    })

    t.end()
  })

  t.test('verify', function (t) {
    t.test('message should be a Buffer', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(message, privateKey)
        var publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.verify(null, signature, publicKey)
      }, new RegExp('^TypeError: ' + messages.MSG32_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('message length is invalid', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage().slice(1)
        var signature = util.getSignature(message, privateKey)
        var publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.verify(message, signature, publicKey)
      }, new RegExp('^RangeError: ' + messages.MSG32_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('signature should be a Buffer', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.verify(message, null, publicKey)
      }, new RegExp('^TypeError: ' + messages.ECDSA_SIGNATURE_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('signature length is invalid', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(message, privateKey).slice(1)
        var publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.verify(message, signature, publicKey)
      }, new RegExp('^RangeError: ' + messages.ECDSA_SIGNATURE_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('signature is invalid (r equal N)', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = Buffer.concat([
          new Buffer(util.ec.n.toArray(null, 32)),
          getRandomBytes(32)
        ])
        var publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.verify(message, signature, publicKey)
      }, new RegExp('^Error: ' + messages.ECDSA_SIGNATURE_PARSE_FAIL + '$'))
      t.end()
    })

    t.test('public key should be a Buffer', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(message, privateKey)
        secp256k1.verify(message, signature, null)
      }, new RegExp('^TypeError: ' + messages.EC_PUBLIC_KEY_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('public key length is invalid', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(message, privateKey)
        var publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        secp256k1.verify(message, signature, publicKey)
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
        secp256k1.verify(message, signature, publicKey)
      }, new RegExp('^Error: ' + messages.EC_PUBLIC_KEY_PARSE_FAIL + '$'))
      t.end()
    })

    t.end()
  })

  t.test('recover', function (t) {
    t.test('message should be a Buffer', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(message, privateKey)
        secp256k1.recover(null, signature, 0)
      }, new RegExp('^TypeError: ' + messages.MSG32_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('message length is invalid', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage().slice(1)
        var signature = util.getSignature(message, privateKey)
        secp256k1.recover(message, signature, 0)
      }, new RegExp('^RangeError: ' + messages.MSG32_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('signature should be a Buffer', function (t) {
      t.throws(function () {
        var message = util.getMessage()
        secp256k1.recover(message, null, 0)
      }, new RegExp('^TypeError: ' + messages.ECDSA_SIGNATURE_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('signature length is invalid', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(message, privateKey).slice(1)
        secp256k1.recover(message, signature, 0)
      }, new RegExp('^RangeError: ' + messages.ECDSA_SIGNATURE_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('signature is invalid (r equal N)', function (t) {
      t.throws(function () {
        var message = util.getMessage()
        var signature = Buffer.concat([
          new Buffer(util.ec.n.toArray(null, 32)),
          getRandomBytes(32)
        ])
        secp256k1.recover(message, signature, 0)
      }, new RegExp('^Error: ' + messages.ECDSA_SIGNATURE_PARSE_FAIL + '$'))
      t.end()
    })

    t.test('recovery should be a Number', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(message, privateKey)
        secp256k1.recover(message, signature, null)
      }, new RegExp('^TypeError: ' + messages.RECOVERY_ID_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('recovery is invalid (equal 4)', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(privateKey, message)
        secp256k1.recover(message, signature, 4)
      }, new RegExp('^RangeError: ' + messages.RECOVERY_ID_VALUE_INVALID + '$'))
      t.end()
    })

    t.test('compressed should be a boolean', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(message, privateKey)
        secp256k1.recover(message, signature, 0, null)
      }, new RegExp('^TypeError: ' + messages.COMPRESSED_TYPE_INVALID + '$'))
      t.end()
    })

    t.end()
  })

  t.test('sign/verify/recover', function (t) {
    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var message = util.getMessage()
      var privateKey = util.getPrivateKey()
      var publicKey = util.getPublicKey(privateKey)
      var expected = util.sign(message, privateKey)

      var sigObj = secp256k1.sign(message, privateKey)
      t.same(sigObj.signature, expected.signatureLowS)
      t.same(sigObj.recovery, expected.recovery)

      var isValid = secp256k1.verify(message, sigObj.signature, publicKey.compressed)
      t.true(isValid)

      var compressed = secp256k1.recover(message, sigObj.signature, sigObj.recovery, true)
      t.same(compressed, publicKey.compressed)

      var uncompressed = secp256k1.recover(message, sigObj.signature, sigObj.recovery, false)
      t.same(uncompressed, publicKey.uncompressed)

      t.end()
    })

    t.end()
  })
}
