'use strict'

var expect = require('chai').expect
var BN = require('bn.js')

var util = require('./util')
var messages = require('../lib/messages')

/**
 * @param {Object} secp256k1
 */
module.exports = function (secp256k1) {
  describe('publicKeyCreate', function () {
    it('should be a Buffer', function () {
      expect(function () {
        secp256k1.publicKeyCreate(null)
      }).to.throw(TypeError, messages.EC_PRIVATE_KEY_TYPE_INVALID)
    })

    it('invalid length', function () {
      expect(function () {
        var privateKey = util.getPrivateKey().slice(1)
        secp256k1.publicKeyCreate(privateKey)
      }).to.throw(RangeError, messages.EC_PRIVATE_KEY_LENGTH_INVALID)
    })

    it('overflow', function () {
      expect(function () {
        var privateKey = new Buffer(util.ec.curve.n.toArray(null, 32))
        secp256k1.publicKeyCreate(privateKey)
      }).to.throw(Error, messages.EC_PUBLIC_KEY_CREATE_FAIL)
    })

    it('equal zero', function () {
      expect(function () {
        var privateKey = new Buffer(util.BN_ZERO.toArray(null, 32))
        secp256k1.publicKeyCreate(privateKey)
      }).to.throw(Error, messages.EC_PUBLIC_KEY_CREATE_FAIL)
    })

    it('compressed should be a boolean', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        secp256k1.publicKeyCreate(privateKey, null)
      }).to.throw(TypeError, messages.COMPRESSED_TYPE_INVALID)
    })

    util.repeatIt('random tests', util.env.repeat, function () {
      var privateKey = util.getPrivateKey()
      var expected = util.getPublicKey(privateKey)

      var compressed = secp256k1.publicKeyCreate(privateKey, true)
      expect(compressed.toString('hex')).to.equal(expected.compressed.toString('hex'))
      var uncompressed = secp256k1.publicKeyCreate(privateKey, false)
      expect(uncompressed.toString('hex')).to.equal(expected.uncompressed.toString('hex'))
    })
  })

  describe('publicKeyConvert', function () {
    it('should be a Buffer', function () {
      expect(function () {
        secp256k1.publicKeyConvert(null)
      }).to.throw(TypeError, messages.EC_PUBLIC_KEY_TYPE_INVALID)
    })

    it('length is invalid', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        secp256k1.publicKeyConvert(publicKey)
      }).to.throw(RangeError, messages.EC_PUBLIC_KEY_LENGTH_INVALID)
    })

    it('compressed should be a boolean', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.publicKeyConvert(publicKey, null)
      }).to.throw(TypeError, messages.COMPRESSED_TYPE_INVALID)
    })

    util.repeatIt('random tests', util.env.repeat, function () {
      var privateKey = util.getPrivateKey()
      var expected = util.getPublicKey(privateKey)

      var compressed = secp256k1.publicKeyConvert(expected.uncompressed, true)
      expect(compressed.toString('hex')).to.equal(expected.compressed.toString('hex'))

      var uncompressed = secp256k1.publicKeyConvert(expected.compressed, false)
      expect(uncompressed.toString('hex')).to.equal(expected.uncompressed.toString('hex'))
    })
  })

  describe('publicKeyVerify', function () {
    it('should be a Buffer', function () {
      expect(function () {
        secp256k1.publicKeyVerify(null)
      }).to.throw(TypeError, messages.EC_PUBLIC_KEY_TYPE_INVALID)
    })

    it('invalid length', function () {
      var privateKey = util.getPrivateKey()
      var publicKey = util.getPublicKey(privateKey).compressed.slice(1)
      expect(secp256k1.publicKeyVerify(publicKey)).to.be.false
    })

    it('invalid first byte', function () {
      var privateKey = util.getPrivateKey()
      var publicKey = util.getPublicKey(privateKey).compressed
      publicKey[0] = 0x01
      expect(secp256k1.publicKeyVerify(publicKey)).to.be.false
    })

    it('x overflow (first byte is 0x03)', function () {
      var publicKey = new Buffer([0x03].concat(util.ec.curve.p.toArray(null, 32)))
      expect(secp256k1.publicKeyVerify(publicKey)).to.be.false
    })

    it('x overflow', function () {
      var publicKey = new Buffer([0x04].concat(util.ec.curve.p.toArray(null, 32)))
      expect(secp256k1.publicKeyVerify(publicKey)).to.be.false
    })

    it('y overflow', function () {
      var publicKey = new Buffer([0x04].concat(new Array(32)).concat(util.ec.curve.p.toArray(null, 32)))
      expect(secp256k1.publicKeyVerify(publicKey)).to.be.false
    })

    it('y is even, first byte is 0x07', function () {
      var publicKey = new Buffer([0x07].concat(new Array(32)).concat(util.ec.curve.p.subn(1).toArray(null, 32)))
      expect(secp256k1.publicKeyVerify(publicKey)).to.be.false
    })

    it('y**2 !== x*x*x + 7', function () {
      var publicKey = Buffer.concat([new Buffer([0x04]), util.getTweak(), util.getTweak()])
      expect(secp256k1.publicKeyVerify(publicKey)).to.be.false
    })

    util.repeatIt('random tests', util.env.repeat, function () {
      var privateKey = util.getPrivateKey()
      var publicKey = util.getPublicKey(privateKey)
      expect(secp256k1.publicKeyVerify(publicKey.compressed)).to.be.true
      expect(secp256k1.publicKeyVerify(publicKey.uncompressed)).to.be.true
    })
  })

  describe('publicKeyTweakAdd', function () {
    it('public key should be a Buffer', function () {
      expect(function () {
        var tweak = util.getTweak()
        secp256k1.publicKeyTweakAdd(null, tweak)
      }).to.throw(TypeError, messages.EC_PUBLIC_KEY_TYPE_INVALID)
    })

    it('public key length is invalid', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        var tweak = util.getTweak()
        secp256k1.publicKeyTweakAdd(publicKey, tweak)
      }).to.throw(RangeError, messages.EC_PUBLIC_KEY_LENGTH_INVALID)
    })

    it('public key is invalid (version is 0x01)', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        publicKey[0] = 0x01
        var tweak = util.getTweak()
        secp256k1.publicKeyTweakAdd(publicKey, tweak)
      }).to.throw(Error, messages.EC_PUBLIC_KEY_PARSE_FAIL)
    })

    it('tweak should be a Buffer', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.publicKeyTweakAdd(publicKey, null)
      }).to.throw(TypeError, messages.TWEAK_TYPE_INVALID)
    })

    it('tweak length length is invalid', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        var tweak = util.getTweak().slice(1)
        secp256k1.publicKeyTweakAdd(publicKey, tweak)
      }).to.throw(RangeError, messages.TWEAK_LENGTH_INVALID)
    })

    it('tweak overflow', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        var tweak = new Buffer(util.ec.curve.n.toArray(null, 32))
        secp256k1.publicKeyTweakAdd(publicKey, tweak)
      }).to.throw(Error, messages.EC_PUBLIC_KEY_TWEAK_ADD_FAIL)
    })

    it('compressed should be a boolean', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        var tweak = util.getTweak()
        secp256k1.publicKeyTweakAdd(publicKey, tweak, null)
      }).to.throw(TypeError, messages.COMPRESSED_TYPE_INVALID)
    })

    util.repeatIt('random tests', util.env.repeat, function () {
      var privateKey = util.getPrivateKey()
      var tweak = util.getTweak()

      var publicPoint = util.ec.g.mul(new BN(privateKey))
      var publicKey = new Buffer(publicPoint.encode(null, true))
      var expected = util.ec.g.mul(new BN(tweak)).add(publicPoint)

      var compressed = secp256k1.publicKeyTweakAdd(publicKey, tweak, true)
      expect(compressed.toString('hex')).to.equal(expected.encode('hex', true))

      var uncompressed = secp256k1.publicKeyTweakAdd(publicKey, tweak, false)
      expect(uncompressed.toString('hex')).to.equal(expected.encode('hex', false))
    })
  })

  describe('publicKeyTweakMul', function () {
    it('public key should be a Buffer', function () {
      expect(function () {
        var tweak = util.getTweak()
        secp256k1.publicKeyTweakMul(null, tweak)
      }).to.throw(TypeError, messages.EC_PUBLIC_KEY_TYPE_INVALID)
    })

    it('public key length is invalid', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        var tweak = util.getTweak()
        secp256k1.publicKeyTweakMul(publicKey, tweak)
      }).to.throw(RangeError, messages.EC_PUBLIC_KEY_LENGTH_INVALID)
    })

    it('public key is invalid (version is 0x01)', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        publicKey[0] = 0x01
        var tweak = util.getTweak()
        secp256k1.publicKeyTweakMul(publicKey, tweak)
      }).to.throw(Error, messages.EC_PUBLIC_KEY_PARSE_FAIL)
    })

    it('tweak should be a Buffer', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.publicKeyTweakMul(publicKey, null)
      }).to.throw(TypeError, messages.TWEAK_TYPE_INVALID)
    })

    it('tweak length is invalid', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        var tweak = util.getTweak().slice(1)
        secp256k1.publicKeyTweakMul(publicKey, tweak)
      }).to.throw(RangeError, messages.TWEAK_LENGTH_INVALID)
    })

    it('tweak is zero', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        var tweak = new Buffer(util.BN_ZERO.toArray(null, 32))
        secp256k1.publicKeyTweakMul(publicKey, tweak)
      }).to.throw(Error, messages.EC_PUBLIC_KEY_TWEAK_MUL_FAIL)
    })

    it('tweak overflow', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        var tweak = new Buffer(util.ec.curve.n.toArray(null, 32))
        secp256k1.publicKeyTweakMul(publicKey, tweak)
      }).to.throw(Error, messages.EC_PUBLIC_KEY_TWEAK_MUL_FAIL)
    })

    it('compressed should be a boolean', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        var tweak = util.getTweak()
        secp256k1.publicKeyTweakMul(publicKey, tweak, null)
      }).to.throw(TypeError, messages.COMPRESSED_TYPE_INVALID)
    })

    util.repeatIt('random tests', util.env.repeat, function () {
      var privateKey = util.getPrivateKey()
      var publicPoint = util.ec.g.mul(new BN(privateKey))
      var publicKey = new Buffer(publicPoint.encode(null, true))
      var tweak = util.getTweak()

      if (new BN(tweak).cmp(util.BN_ZERO) === 0) {
        return expect(function () {
          secp256k1.publicKeyTweakMul(publicKey, tweak)
        }).to.throw(Error, messages.EC_PUBLIC_KEY_TWEAK_MUL_FAIL)
      }

      var expected = publicPoint.mul(tweak)

      var compressed = secp256k1.publicKeyTweakMul(publicKey, tweak, true)
      expect(compressed.toString('hex')).to.equal(expected.encode('hex', true))

      var uncompressed = secp256k1.publicKeyTweakMul(publicKey, tweak, false)
      expect(uncompressed.toString('hex')).to.equal(expected.encode('hex', false))
    })
  })

  describe('publicKeyCombine', function () {
    it('public keys should be an Array', function () {
      expect(function () {
        secp256k1.publicKeyCombine(null)
      }).to.throw(TypeError, messages.EC_PUBLIC_KEYS_TYPE_INVALID)
    })

    it('public keys should have length greater that zero', function () {
      expect(function () {
        secp256k1.publicKeyCombine([])
      }).to.throw(RangeError, messages.EC_PUBLIC_KEYS_LENGTH_INVALID)
    })

    it('public key should be a Buffer', function () {
      expect(function () {
        secp256k1.publicKeyCombine([null])
      }).to.throw(TypeError, messages.EC_PUBLIC_KEY_TYPE_INVALID)
    })

    it('public key length is invalid', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        secp256k1.publicKeyCombine([publicKey])
      }).to.throw(RangeError, messages.EC_PUBLIC_KEY_LENGTH_INVALID)
    })

    it('public key is invalid (version is 0x01)', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        publicKey[0] = 0x01
        secp256k1.publicKeyCombine([publicKey])
      }).to.throw(Error, messages.EC_PUBLIC_KEY_PARSE_FAIL)
    })

    it('compressed should be a boolean', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.publicKeyCombine([publicKey], null)
      }).to.throw(TypeError, messages.COMPRESSED_TYPE_INVALID)
    })

    it('P + (-P) = 0', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var publicKey1 = util.getPublicKey(privateKey).compressed
        var publicKey2 = new Buffer(publicKey1)
        publicKey2[0] = publicKey2[0] ^ 0x01
        secp256k1.publicKeyCombine([publicKey1, publicKey2], true)
      }).to.throw(messages.EC_PUBLIC_KEY_COMBINE_FAIL)
    })

    util.repeatIt('random tests', util.env.repeat, function () {
      var cnt = 1 + Math.floor(Math.random() * 3) // 1 <= cnt <= 3
      var privateKeys = []
      while (privateKeys.length < cnt) {
        privateKeys.push(util.getPrivateKey())
      }
      var publicKeys = privateKeys.map(function (privateKey) {
        return util.getPublicKey(privateKey).compressed
      })

      var expected = util.ec.g.mul(new BN(privateKeys[0]))
      for (var i = 1; i < privateKeys.length; ++i) {
        var publicPoint = util.ec.g.mul(new BN(privateKeys[i]))
        expected = expected.add(publicPoint)
      }

      var compressed = secp256k1.publicKeyCombine(publicKeys, true)
      expect(compressed.toString('hex')).to.equal(expected.encode('hex', true))

      var uncompressed = secp256k1.publicKeyCombine(publicKeys, false)
      expect(uncompressed.toString('hex')).to.equal(expected.encode('hex', false))
    })
  })
}
