var expect = require('chai').expect
var BigInteger = require('bigi')
var ECKey = require('eckey')
var ecurve = require('ecurve')

var util = require('./util')

var ecparams = ecurve.getCurveByName('secp256k1')

/**
 * @param {Object} secp256k1
 * @param {Object} opts
 * @param {number} opts.repeat
 */
module.exports = function (secp256k1, opts) {
  describe('publicKeyCreate', function () {
    it('should be a Buffer', function () {
      expect(function () {
        secp256k1.publicKeyCreate(null)
      }).to.throw(TypeError, /secret/)
    })

    it('invalid length', function () {
      expect(function () {
        secp256k1.publicKeyCreate(util.getPrivateKey().slice(1))
      }).to.throw(RangeError, /secret/)
    })

    it('zero key', function () {
      expect(function () {
        var privKey = BigInteger.ZERO.toBuffer(32)
        secp256k1.publicKeyCreate(privKey)
      }).to.throw(Error, /secret/)
    })

    it('equal to N', function () {
      expect(function () {
        var privKey = util.ecparams.n.toBuffer(32)
        secp256k1.publicKeyCreate(privKey)
      }).to.throw(Error, /secret/)
    })

    util.repeatIt('random tests', opts.repeat, function () {
      var privKey = util.getPrivateKey()
      var pubKey = secp256k1.publicKeyCreate(privKey)
      var eckey = new ECKey(privKey)
      expect(pubKey.toString('hex')).to.equal(eckey.publicKey.toString('hex'))
    })
  })

  describe('publicKeyConvert', function () {
    it('should be a Buffer', function () {
      expect(function () {
        secp256k1.publicKeyConvert(null)
      }).to.throw(TypeError, /public/)
    })

    it('public key length is invalid', function () {
      expect(function () {
        secp256k1.publicKeyConvert(util.getPublicKey().slice(1))
      }).to.throw(RangeError, /public/)
    })

    it('public key is invalid (version is 0x01)', function () {
      var pubKey = util.getPublicKey()
      pubKey[0] = 0x01
      expect(function () {
        secp256k1.publicKeyConvert(pubKey)
      }).to.throw(Error)
    })

    it('compressed shoule be a boolean', function () {
      expect(function () {
        secp256k1.publicKeyConvert(util.getPublicKey(), null)
      }).to.throw(TypeError, /compressed/)
    })

    util.repeatIt('random tests', opts.repeat, function () {
      var privKey = util.getPrivateKey()
      var pubKeys = {
        compressed: new ECKey(privKey, true).publicKey,
        uncompressed: new ECKey(privKey, false).publicKey
      }
      expect({
        compressed: secp256k1.publicKeyConvert(pubKeys.uncompressed, true),
        uncompressed: secp256k1.publicKeyConvert(pubKeys.compressed, false)
      }).to.deep.equal(pubKeys)
    })
  })

  describe('publicKeyVerify', function () {
    it('should be a Buffer', function () {
      expect(function () {
        secp256k1.publicKeyVerify(null)
      }).to.throw(TypeError)
    })

    it('invalid length', function () {
      expect(secp256k1.publicKeyVerify(util.getPublicKey().slice(1))).to.be.false
    })

    it('invalid key', function () {
      var pubKey = util.getPublicKey()
      pubKey[0] = 0x01
      expect(secp256k1.publicKeyVerify(pubKey)).to.be.false
    })

    util.repeatIt('random tests', opts.repeat, function () {
      var pubKey = util.getPublicKey()
      expect(secp256k1.publicKeyVerify(pubKey)).to.be.true
    })
  })

  describe('publicKeyTweakAdd', function () {
    it('public key should be a Buffer', function () {
      expect(function () {
        secp256k1.publicKeyTweakAdd(null, util.getTweak())
      }).to.throw(TypeError, /public/)
    })

    it('tweak should be a Buffer', function () {
      expect(function () {
        secp256k1.publicKeyTweakAdd(util.getPublicKey(), null)
      }).to.throw(TypeError, /tweak/)
    })

    it('public key length is invalid', function () {
      expect(function () {
        secp256k1.publicKeyTweakAdd(util.getPublicKey().slice(1), util.getTweak())
      }).to.throw(RangeError, /public/)
    })

    it('tweak length length is invalid', function () {
      expect(function () {
        secp256k1.publicKeyTweakAdd(util.getPublicKey(), util.getTweak().slice(1))
      }).to.throw(RangeError, /tweak/)
    })

    it('public key is invalid (version is 0x01)', function () {
      var pubKey = util.getPublicKey()
      pubKey[0] = 0x01
      expect(function () {
        secp256k1.publicKeyTweakAdd(pubKey, util.getTweak())
      }).to.throw(Error, /public/)
    })

    it('tweak overflow', function () {
      expect(function () {
        secp256k1.publicKeyTweakAdd(util.getPublicKey(), util.ecparams.n.toBuffer(32))
      }).to.throw(Error, /range/)
    })

    util.repeatIt('random tests', opts.repeat, function () {
      var eckey = new ECKey(util.getPrivateKey())
      var tweak = util.getTweak()

      var expected = ecparams.G.multiply(BigInteger.fromBuffer(tweak)).add(eckey.publicPoint).getEncoded(true)
      var result = secp256k1.publicKeyTweakAdd(eckey.publicKey, tweak)
      expect(expected.toString('hex')).to.equal(result.toString('hex'))
    })
  })

  describe('publicKeyTweakMul', function () {
    it('public key should be a Buffer', function () {
      expect(function () {
        secp256k1.publicKeyTweakMul(null, util.getTweak())
      }).to.throw(TypeError, /public/)
    })

    it('tweak should be a Buffer', function () {
      expect(function () {
        secp256k1.publicKeyTweakMul(util.getPublicKey(), null)
      }).to.throw(TypeError, /tweak/)
    })

    it('public key length is invalid', function () {
      expect(function () {
        secp256k1.publicKeyTweakMul(util.getPublicKey().slice(1), util.getTweak())
      }).to.throw(RangeError, /public/)
    })

    it('tweak length is invalid', function () {
      expect(function () {
        secp256k1.publicKeyTweakMul(util.getPublicKey(), util.getTweak().slice(1))
      }).to.throw(RangeError, /tweak/)
    })

    it('public key is invalid (version is 0x01)', function () {
      var pubKey = util.getPublicKey()
      pubKey[0] = 0x01
      expect(function () {
        secp256k1.publicKeyTweakMul(pubKey, util.getTweak())
      }).to.throw(Error, /public/)
    })

    it('tweak is zero', function () {
      expect(function () {
        secp256k1.publicKeyTweakMul(util.getPublicKey(), BigInteger.ZERO.toBuffer(32))
      }).to.throw(Error, /range/)
    })

    it('tweak overflow', function () {
      expect(function () {
        secp256k1.publicKeyTweakMul(util.getPublicKey(), util.ecparams.n.toBuffer(32))
      }).to.throw(Error, /range/)
    })

    util.repeatIt('random tests', opts.repeat, function () {
      var eckey = new ECKey(util.getPrivateKey(), false)
      var tweak = BigInteger.fromBuffer(util.getTweak())

      if (tweak.compareTo(BigInteger.ZERO) === 0) {
        return expect(function () {
          secp256k1.publicKeyTweakMul(eckey.publicKey, tweak.toBuffer(32))
        }).to.throw(Error, /range/)
      }

      var expected = eckey.publicPoint.multiply(tweak).getEncoded(true)
      var result = secp256k1.publicKeyTweakMul(eckey.publicKey, tweak.toBuffer(32))
      expect(result.toString('hex')).to.equal(expected.toString('hex'))
    })
  })

  describe('publicKeyCombine', function () {
    it('public keys should be an Array', function () {
      expect(function () {
        secp256k1.publicKeyCombine(null)
      }).to.throw(TypeError, /public keys/)
    })

    it('public keys should have length greater that zero', function () {
      expect(function () {
        secp256k1.publicKeyCombine([])
      }).to.throw(RangeError, /public keys/)
    })

    it('public key should be a Buffer', function () {
      expect(function () {
        secp256k1.publicKeyCombine([null])
      }).to.throw(TypeError, /public key/)
    })

    it('public key length is invalid', function () {
      expect(function () {
        secp256k1.publicKeyCombine([new Buffer(32)])
      }).to.throw(RangeError, /public key/)
    })

    it('public key is invalid (version is 0x01)', function () {
      var pubKey = util.getPublicKey()
      pubKey[0] = 0x01
      expect(function () {
        secp256k1.publicKeyCombine([pubKey])
      }).to.throw(Error)
    })

    util.repeatIt('random tests', opts.repeat, function () {
      var cnt = 1 + Math.floor(Math.random() * 3) // 1 <= cnt <= 3
      var keys = []
      while (keys.length < cnt) {
        keys.push(new ECKey(util.getPrivateKey()))
      }
      var pubKeys = keys.map(function (key) { return key.publicKey })

      var publicPoint = keys[0].publicPoint
      for (var i = 1; i < keys.length; ++i) {
        publicPoint = publicPoint.add(keys[i].publicPoint)
      }
      var expected = publicPoint.getEncoded(true)

      var result = secp256k1.publicKeyCombine(pubKeys)
      expect(result.toString('hex')).to.equal(expected.toString('hex'))
    })
  })
}

