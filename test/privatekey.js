'use strict'
var BN = require('bn.js')
var messages = require('../lib/messages')

var util = require('./util')

module.exports = function (t, secp256k1) {
  t.test('privateKeyVerify', function (t) {
    t.test('should be a Buffer', function (t) {
      t.throws(function () {
        secp256k1.privateKeyVerify(null)
      }, new RegExp('^TypeError: ' + messages.EC_PRIVATE_KEY_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('invalid length', function (t) {
      var privateKey = util.getPrivateKey().slice(1)
      t.false(secp256k1.privateKeyVerify(privateKey))
      t.end()
    })

    t.test('zero key', function (t) {
      var privateKey = util.BN_ZERO.toArrayLike(Buffer, 'be', 32)
      t.false(secp256k1.privateKeyVerify(privateKey))
      t.end()
    })

    t.test('equal to N', function (t) {
      var privateKey = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
      t.false(secp256k1.privateKeyVerify(privateKey))
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var privateKey = util.getPrivateKey()
      t.true(secp256k1.privateKeyVerify(privateKey))
      t.end()
    })

    t.end()
  })

  t.test('privateKeyExport', function (t) {
    t.test('private key should be a Buffer', function (t) {
      t.throws(function () {
        secp256k1.privateKeyExport(null)
      }, new RegExp('^TypeError: ' + messages.EC_PRIVATE_KEY_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('private key length is invalid', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey().slice(1)
        secp256k1.privateKeyExport(privateKey)
      }, new RegExp('^RangeError: ' + messages.EC_PRIVATE_KEY_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('compressed should be a boolean', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        secp256k1.privateKeyExport(privateKey, null)
      }, new RegExp('^TypeError: ' + messages.COMPRESSED_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('private key is invalid', function (t) {
      t.throws(function () {
        var privateKey = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
        secp256k1.privateKeyExport(privateKey)
      }, new RegExp('^Error: ' + messages.EC_PRIVATE_KEY_EXPORT_DER_FAIL + '$'))
      t.end()
    })

    t.end()
  })

  t.test('privateKeyImport', function (t) {
    t.test('should be a Buffer', function (t) {
      t.throws(function () {
        secp256k1.privateKeyImport(null)
      }, new RegExp('^TypeError: ' + messages.EC_PRIVATE_KEY_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('invalid format', function (t) {
      t.throws(function () {
        var buffer = new Buffer([0x00])
        secp256k1.privateKeyImport(buffer)
      }, new RegExp('^Error: ' + messages.EC_PRIVATE_KEY_IMPORT_DER_FAIL + '$'))
      t.end()
    })

    t.end()
  })

  t.test('privateKeyExport/privateKeyImport', function (t) {
    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var privateKey = util.getPrivateKey()

      var der1 = secp256k1.privateKeyExport(privateKey, true)
      var privateKey1 = secp256k1.privateKeyImport(der1)
      t.same(privateKey1, privateKey)

      var der2 = secp256k1.privateKeyExport(privateKey, false)
      var privateKey2 = secp256k1.privateKeyImport(der2)
      t.same(privateKey2, privateKey)

      t.end()
    })

    t.end()
  })

  t.test('privateKeyTweakAdd', function (t) {
    t.test('private key should be a Buffer', function (t) {
      t.throws(function () {
        var tweak = util.getTweak()
        secp256k1.privateKeyTweakAdd(null, tweak)
      }, new RegExp('^TypeError: ' + messages.EC_PRIVATE_KEY_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('private key length is invalid', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey().slice(1)
        var tweak = util.getTweak()
        secp256k1.privateKeyTweakAdd(privateKey, tweak)
      }, new RegExp('^RangeError: ' + messages.EC_PRIVATE_KEY_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('tweak should be a Buffer', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        secp256k1.privateKeyTweakAdd(privateKey, null)
      }, new RegExp('^TypeError: ' + messages.TWEAK_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('tweak length is invalid', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var tweak = util.getTweak().slice(1)
        secp256k1.privateKeyTweakAdd(privateKey, tweak)
      }, new RegExp('^RangeError: ' + messages.TWEAK_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('tweak overflow', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var tweak = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
        secp256k1.privateKeyTweakAdd(privateKey, tweak)
      }, new RegExp('^Error: ' + messages.EC_PRIVATE_KEY_TWEAK_ADD_FAIL + '$'))
      t.end()
    })

    t.test('result is zero: (N - 1) + 1', function (t) {
      t.throws(function () {
        var privateKey = util.ec.curve.n.sub(util.BN_ONE).toArrayLike(Buffer, 'be', 32)
        var tweak = util.BN_ONE.toArrayLike(Buffer, 'be', 32)
        secp256k1.privateKeyTweakAdd(privateKey, tweak)
      }, new RegExp('^Error: ' + messages.EC_PRIVATE_KEY_TWEAK_ADD_FAIL + '$'))
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var privateKey = util.getPrivateKey()
      var tweak = util.getTweak()

      var expected = new BN(privateKey).add(new BN(tweak)).mod(util.ec.curve.n)
      if (expected.cmp(util.BN_ZERO) === 0) {
        t.throws(function () {
          secp256k1.privateKeyTweakAdd(privateKey, tweak)
        }, new RegExp('^Error: ' + messages.EC_PRIVATE_KEY_TWEAK_ADD_FAIL + '$'))
      } else {
        var result = secp256k1.privateKeyTweakAdd(privateKey, tweak)
        t.same(result.toString('hex'), expected.toString(16, 64))
      }

      t.end()
    })

    t.end()
  })

  t.test('privateKeyTweakMul', function (t) {
    t.test('private key should be a Buffer', function (t) {
      t.throws(function () {
        var tweak = util.getTweak()
        secp256k1.privateKeyTweakMul(null, tweak)
      }, new RegExp('^TypeError: ' + messages.EC_PRIVATE_KEY_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('private key length is invalid', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey().slice(1)
        var tweak = util.getTweak()
        secp256k1.privateKeyTweakMul(privateKey, tweak)
      }, new RegExp('^RangeError: ' + messages.EC_PRIVATE_KEY_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('tweak should be a Buffer', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        secp256k1.privateKeyTweakMul(privateKey, null)
      }, new RegExp('^TypeError: ' + messages.TWEAK_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('tweak length is invalid', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var tweak = util.getTweak().slice(1)
        secp256k1.privateKeyTweakMul(privateKey, tweak)
      }, new RegExp('^RangeError: ' + messages.TWEAK_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('tweak equal N', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var tweak = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
        secp256k1.privateKeyTweakMul(privateKey, tweak)
      }, new RegExp('^Error: ' + messages.EC_PRIVATE_KEY_TWEAK_MUL_FAIL + '$'))
      t.end()
    })

    t.test('tweak is 0', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var tweak = util.BN_ZERO.toArrayLike(Buffer, 'be', 32)
        secp256k1.privateKeyTweakMul(privateKey, tweak)
      }, new RegExp('^Error: ' + messages.EC_PRIVATE_KEY_TWEAK_MUL_FAIL + '$'))
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var privateKey = util.getPrivateKey()
      var tweak = util.getTweak()

      if (new BN(tweak).cmp(util.BN_ZERO) === 0) {
        t.throws(function () {
          secp256k1.privateKeyTweakMul(privateKey, tweak)
        }, new RegExp('^Error: ' + messages.EC_PRIVATE_KEY_TWEAK_MUL_FAIL + '$'))
      } else {
        var expected = new BN(privateKey).mul(new BN(tweak)).mod(util.ec.curve.n)
        var result = secp256k1.privateKeyTweakMul(privateKey, tweak)
        t.same(result.toString('hex'), expected.toString(16, 64))
      }

      t.end()
    })

    t.end()
  })
}
