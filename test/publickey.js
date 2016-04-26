'use strict'
var BN = require('bn.js')
var messages = require('../lib/messages')

var util = require('./util')

module.exports = function (t, secp256k1) {
  t.test('publicKeyCreate', function (t) {
    t.test('should be a Buffer', function (t) {
      t.throws(function () {
        secp256k1.publicKeyCreate(null)
      }, new RegExp('^TypeError: ' + messages.EC_PRIVATE_KEY_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('invalid length', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey().slice(1)
        secp256k1.publicKeyCreate(privateKey)
      }, new RegExp('^RangeError: ' + messages.EC_PRIVATE_KEY_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('overflow', function (t) {
      t.throws(function () {
        var privateKey = new Buffer(util.ec.curve.n.toArray(null, 32))
        secp256k1.publicKeyCreate(privateKey)
      }, new RegExp('^Error: ' + messages.EC_PUBLIC_KEY_CREATE_FAIL + '$'))
      t.end()
    })

    t.test('equal zero', function (t) {
      t.throws(function () {
        var privateKey = util.BN_ZERO.toArrayLike(Buffer, null, 32)
        secp256k1.publicKeyCreate(privateKey)
      }, new RegExp('^Error: ' + messages.EC_PUBLIC_KEY_CREATE_FAIL + '$'))
      t.end()
    })

    t.test('compressed should be a boolean', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        secp256k1.publicKeyCreate(privateKey, null)
      }, new RegExp('^TypeError: ' + messages.COMPRESSED_TYPE_INVALID + '$'))
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var privateKey = util.getPrivateKey()
      var expected = util.getPublicKey(privateKey)

      var compressed = secp256k1.publicKeyCreate(privateKey, true)
      t.deepEqual(compressed, expected.compressed)

      var uncompressed = secp256k1.publicKeyCreate(privateKey, false)
      t.deepEqual(uncompressed, expected.uncompressed)

      t.end()
    })

    t.end()
  })

  t.test('publicKeyConvert', function (t) {
    t.test('should be a Buffer', function (t) {
      t.throws(function () {
        secp256k1.publicKeyConvert(null)
      }, new RegExp('^TypeError: ' + messages.EC_PUBLIC_KEY_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('length is invalid', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        secp256k1.publicKeyConvert(publicKey)
      }, new RegExp('^RangeError: ' + messages.EC_PUBLIC_KEY_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('compressed should be a boolean', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.publicKeyConvert(publicKey, null)
      }, new RegExp('^TypeError: ' + messages.COMPRESSED_TYPE_INVALID + '$'))
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var privateKey = util.getPrivateKey()
      var expected = util.getPublicKey(privateKey)

      var compressed = secp256k1.publicKeyConvert(expected.uncompressed, true)
      t.deepEqual(compressed, expected.compressed)

      var uncompressed = secp256k1.publicKeyConvert(expected.compressed, false)
      t.deepEqual(uncompressed, expected.uncompressed)

      t.end()
    })

    t.end()
  })

  t.test('publicKeyVerify', function (t) {
    t.test('should be a Buffer', function (t) {
      t.throws(function () {
        secp256k1.publicKeyVerify(null)
      }, new RegExp('^TypeError: ' + messages.EC_PUBLIC_KEY_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('invalid length', function (t) {
      var privateKey = util.getPrivateKey()
      var publicKey = util.getPublicKey(privateKey).compressed.slice(1)
      t.false(secp256k1.publicKeyVerify(publicKey))
      t.end()
    })

    t.test('invalid first byte', function (t) {
      var privateKey = util.getPrivateKey()
      var publicKey = util.getPublicKey(privateKey).compressed
      publicKey[0] = 0x01
      t.false(secp256k1.publicKeyVerify(publicKey))
      t.end()
    })

    t.test('x overflow (first byte is 0x03)', function (t) {
      var publicKey = new Buffer([0x03].concat(util.ec.curve.p.toArray(null, 32)))
      t.false(secp256k1.publicKeyVerify(publicKey))
      t.end()
    })

    t.test('x overflow', function (t) {
      var publicKey = new Buffer([0x04].concat(util.ec.curve.p.toArray(null, 32)))
      t.false(secp256k1.publicKeyVerify(publicKey))
      t.end()
    })

    t.test('y overflow', function (t) {
      var publicKey = new Buffer([0x04].concat(new Array(32)).concat(util.ec.curve.p.toArray(null, 32)))
      t.false(secp256k1.publicKeyVerify(publicKey))
      t.end()
    })

    t.test('y is even, first byte is 0x07', function (t) {
      var publicKey = new Buffer([0x07].concat(new Array(32)).concat(util.ec.curve.p.subn(1).toArray(null, 32)))
      t.false(secp256k1.publicKeyVerify(publicKey))
      t.end()
    })

    t.test('y**2 !== x*x*x + 7', function (t) {
      var publicKey = Buffer.concat([new Buffer([0x04]), util.getTweak(), util.getTweak()])
      t.false(secp256k1.publicKeyVerify(publicKey))
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var privateKey = util.getPrivateKey()
      var publicKey = util.getPublicKey(privateKey)
      t.true(secp256k1.publicKeyVerify(publicKey.compressed))
      t.true(secp256k1.publicKeyVerify(publicKey.uncompressed))
      t.end()
    })

    t.end()
  })

  t.test('publicKeyTweakAdd', function (t) {
    t.test('public key should be a Buffer', function (t) {
      t.throws(function () {
        var tweak = util.getTweak()
        secp256k1.publicKeyTweakAdd(null, tweak)
      }, new RegExp('^TypeError: ' + messages.EC_PUBLIC_KEY_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('public key length is invalid', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        var tweak = util.getTweak()
        secp256k1.publicKeyTweakAdd(publicKey, tweak)
      }, new RegExp('^RangeError: ' + messages.EC_PUBLIC_KEY_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('public key is invalid (version is 0x01)', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        publicKey[0] = 0x01
        var tweak = util.getTweak()
        secp256k1.publicKeyTweakAdd(publicKey, tweak)
      }, new RegExp('^Error: ' + messages.EC_PUBLIC_KEY_PARSE_FAIL + '$'))
      t.end()
    })

    t.test('tweak should be a Buffer', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.publicKeyTweakAdd(publicKey, null)
      }, new RegExp('^TypeError: ' + messages.TWEAK_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('tweak length length is invalid', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        var tweak = util.getTweak().slice(1)
        secp256k1.publicKeyTweakAdd(publicKey, tweak)
      }, new RegExp('^RangeError: ' + messages.TWEAK_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('tweak overflow', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        var tweak = new Buffer(util.ec.curve.n.toArray(null, 32))
        secp256k1.publicKeyTweakAdd(publicKey, tweak)
      }, new RegExp('^Error: ' + messages.EC_PUBLIC_KEY_TWEAK_ADD_FAIL + '$'))
      t.end()
    })

    t.test('compressed should be a boolean', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        var tweak = util.getTweak()
        secp256k1.publicKeyTweakAdd(publicKey, tweak, null)
      }, new RegExp('^TypeError: ' + messages.COMPRESSED_TYPE_INVALID + '$'))
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var privateKey = util.getPrivateKey()
      var tweak = util.getTweak()

      var publicPoint = util.ec.g.mul(new BN(privateKey))
      var publicKey = new Buffer(publicPoint.encode(null, true))
      var expected = util.ec.g.mul(new BN(tweak)).add(publicPoint)

      var compressed = secp256k1.publicKeyTweakAdd(publicKey, tweak, true)
      t.equal(compressed.toString('hex'), expected.encode('hex', true))

      var uncompressed = secp256k1.publicKeyTweakAdd(publicKey, tweak, false)
      t.equal(uncompressed.toString('hex'), expected.encode('hex', false))

      t.end()
    })

    t.end()
  })

  t.test('publicKeyTweakMul', function (t) {
    t.test('public key should be a Buffer', function (t) {
      t.throws(function () {
        var tweak = util.getTweak()
        secp256k1.publicKeyTweakMul(null, tweak)
      }, new RegExp('^TypeError: ' + messages.EC_PUBLIC_KEY_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('public key length is invalid', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        var tweak = util.getTweak()
        secp256k1.publicKeyTweakMul(publicKey, tweak)
      }, new RegExp('^RangeError: ' + messages.EC_PUBLIC_KEY_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('public key is invalid (version is 0x01)', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        publicKey[0] = 0x01
        var tweak = util.getTweak()
        secp256k1.publicKeyTweakMul(publicKey, tweak)
      }, new RegExp('^Error: ' + messages.EC_PUBLIC_KEY_PARSE_FAIL + '$'))
      t.end()
    })

    t.test('tweak should be a Buffer', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.publicKeyTweakMul(publicKey, null)
      }, new RegExp('^TypeError: ' + messages.TWEAK_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('tweak length is invalid', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        var tweak = util.getTweak().slice(1)
        secp256k1.publicKeyTweakMul(publicKey, tweak)
      }, new RegExp('^RangeError: ' + messages.TWEAK_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('tweak is zero', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        var tweak = util.BN_ZERO.toArrayLike(Buffer, null, 32)
        secp256k1.publicKeyTweakMul(publicKey, tweak)
      }, new RegExp('^Error: ' + messages.EC_PUBLIC_KEY_TWEAK_MUL_FAIL + '$'))
      t.end()
    })

    t.test('tweak overflow', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        var tweak = new Buffer(util.ec.curve.n.toArray(null, 32))
        secp256k1.publicKeyTweakMul(publicKey, tweak)
      }, new RegExp('^Error: ' + messages.EC_PUBLIC_KEY_TWEAK_MUL_FAIL + '$'))
      t.end()
    })

    t.test('compressed should be a boolean', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        var tweak = util.getTweak()
        secp256k1.publicKeyTweakMul(publicKey, tweak, null)
      }, new RegExp('^TypeError: ' + messages.COMPRESSED_TYPE_INVALID + '$'))
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var privateKey = util.getPrivateKey()
      var publicPoint = util.ec.g.mul(new BN(privateKey))
      var publicKey = new Buffer(publicPoint.encode(null, true))
      var tweak = util.getTweak()

      if (new BN(tweak).cmp(util.BN_ZERO) === 0) {
        t.throws(function () {
          secp256k1.publicKeyTweakMul(publicKey, tweak)
        }, new RegExp('^Error: ' + messages.EC_PUBLIC_KEY_TWEAK_MUL_FAIL + '$'))
      } else {
        var expected = publicPoint.mul(tweak)

        var compressed = secp256k1.publicKeyTweakMul(publicKey, tweak, true)
        t.equal(compressed.toString('hex'), expected.encode('hex', true))

        var uncompressed = secp256k1.publicKeyTweakMul(publicKey, tweak, false)
        t.equal(uncompressed.toString('hex'), expected.encode('hex', false))
      }

      t.end()
    })
  })

  t.test('publicKeyCombine', function (t) {
    t.test('public keys should be an Array', function (t) {
      t.throws(function () {
        secp256k1.publicKeyCombine(null)
      }, new RegExp('^TypeError: ' + messages.EC_PUBLIC_KEYS_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('public keys should have length greater that zero', function (t) {
      t.throws(function () {
        secp256k1.publicKeyCombine([])
      }, new RegExp('^RangeError: ' + messages.EC_PUBLIC_KEYS_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('public key should be a Buffer', function (t) {
      t.throws(function () {
        secp256k1.publicKeyCombine([null])
      }, new RegExp('^TypeError: ' + messages.EC_PUBLIC_KEY_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('public key length is invalid', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        secp256k1.publicKeyCombine([publicKey])
      }, new RegExp('^RangeError: ' + messages.EC_PUBLIC_KEY_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('public key is invalid (version is 0x01)', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        publicKey[0] = 0x01
        secp256k1.publicKeyCombine([publicKey])
      }, new RegExp('^Error: ' + messages.EC_PUBLIC_KEY_PARSE_FAIL + '$'))
      t.end()
    })

    t.test('compressed should be a boolean', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.publicKeyCombine([publicKey], null)
      }, new RegExp('^TypeError: ' + messages.COMPRESSED_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('P + (-P) = 0', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var publicKey1 = util.getPublicKey(privateKey).compressed
        var publicKey2 = new Buffer(publicKey1)
        publicKey2[0] = publicKey2[0] ^ 0x01
        secp256k1.publicKeyCombine([publicKey1, publicKey2], true)
      }, new RegExp('^Error: ' + messages.EC_PUBLIC_KEY_COMBINE_FAIL + '$'))
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var cnt = 1 + Math.floor(Math.random() * 3) // 1 <= cnt <= 3
      var privateKeys = []
      while (privateKeys.length < cnt) privateKeys.push(util.getPrivateKey())
      var publicKeys = privateKeys.map(function (privateKey) {
        return util.getPublicKey(privateKey).compressed
      })

      var expected = util.ec.g.mul(new BN(privateKeys[0]))
      for (var i = 1; i < privateKeys.length; ++i) {
        var publicPoint = util.ec.g.mul(new BN(privateKeys[i]))
        expected = expected.add(publicPoint)
      }

      var compressed = secp256k1.publicKeyCombine(publicKeys, true)
      t.equal(compressed.toString('hex'), expected.encode('hex', true))

      var uncompressed = secp256k1.publicKeyCombine(publicKeys, false)
      t.equal(uncompressed.toString('hex'), expected.encode('hex', false))

      t.end()
    })

    t.end()
  })
}
