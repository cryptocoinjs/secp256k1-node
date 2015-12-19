var expect = require('chai').expect
var BN = require('bn.js')

var util = require('./util')

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
      }).to.throw(TypeError, 'private key should be a Buffer')
    })

    it('invalid length', function () {
      expect(function () {
        var privateKey = util.getPrivateKey().slice(1)
        secp256k1.publicKeyCreate(privateKey)
      }).to.throw(RangeError, 'private key length is invalid')
    })

    it('zero key', function () {
      expect(function () {
        var privateKey = new Buffer(util.BN_ZERO.toArray(null, 32))
        secp256k1.publicKeyCreate(privateKey)
      }).to.throw(Error, 'private was invalid, try again')
    })

    it('equal to N', function () {
      expect(function () {
        var privateKey = new Buffer(util.ec.curve.n.toArray(null, 32))
        secp256k1.publicKeyCreate(privateKey)
      }).to.throw(Error, 'private was invalid, try again')
    })

    it('compressed should be a boolean', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        secp256k1.publicKeyCreate(privateKey, null)
      }).to.throw(TypeError, 'compressed should be a boolean')
    })

    util.repeatIt('random tests', opts.repeat, function () {
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
      }).to.throw(TypeError, 'public key should be a Buffer')
    })

    it('length is invalid', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed.slice(1)
        secp256k1.publicKeyConvert(publicKey)
      }).to.throw(RangeError, 'public key length is invalid')
    })

    it('invalid format (version is 0x01)', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed
        publicKey[0] = 0x01
        secp256k1.publicKeyConvert(publicKey)
      }).to.throw(Error, 'the public key could not be parsed or is invalid')
    })

    it('compressed should be a boolean', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed
        secp256k1.publicKeyConvert(publicKey, null)
      }).to.throw(TypeError, 'compressed should be a boolean')
    })

    util.repeatIt('random tests', opts.repeat, function () {
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
      }).to.throw(TypeError, 'public key should be a Buffer')
    })

    it('invalid length', function () {
      var publicKey = util.getPublicKey().compressed.slice(1)
      expect(secp256k1.publicKeyVerify(publicKey)).to.be.false
    })

    it('invalid key', function () {
      var publicKey = util.getPublicKey().compressed
      publicKey[0] = 0x01
      expect(secp256k1.publicKeyVerify(publicKey)).to.be.false
    })

    util.repeatIt('random tests', opts.repeat, function () {
      var publicKey = util.getPublicKey()
      expect(secp256k1.publicKeyVerify(publicKey.compressed)).to.be.true
      expect(secp256k1.publicKeyVerify(publicKey.uncompressed)).to.be.true
    })
  })

  describe('publicKeyTweakAdd', function () {
    it('public key should be a Buffer', function () {
      expect(function () {
        var tweak = util.getTweak()
        secp256k1.publicKeyTweakAdd(null, tweak)
      }).to.throw(TypeError, 'public key should be a Buffer')
    })

    it('public key length is invalid', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed.slice(1)
        var tweak = util.getTweak()
        secp256k1.publicKeyTweakAdd(publicKey, tweak)
      }).to.throw(RangeError, 'public key length is invalid')
    })

    it('public key is invalid (version is 0x01)', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed
        publicKey[0] = 0x01
        var tweak = util.getTweak()
        secp256k1.publicKeyTweakAdd(publicKey, tweak)
      }).to.throw(Error, 'the public key could not be parsed or is invalid')
    })

    it('tweak should be a Buffer', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed
        secp256k1.publicKeyTweakAdd(publicKey, null)
      }).to.throw(TypeError, 'tweak should be a Buffer')
    })

    it('tweak length length is invalid', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed
        var tweak = util.getTweak().slice(1)
        secp256k1.publicKeyTweakAdd(publicKey, tweak)
      }).to.throw(RangeError, 'tweak length is invalid')
    })

    it('tweak overflow', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed
        var tweak = new Buffer(util.ec.curve.n.toArray(null, 32))
        secp256k1.publicKeyTweakAdd(publicKey, tweak)
      }).to.throw(Error, 'tweak out of range or resulting public key is invalid')
    })

    it('compressed should be a boolean', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed
        var tweak = util.getTweak()
        secp256k1.publicKeyTweakAdd(publicKey, tweak, null)
      }).to.throw(TypeError, 'compressed should be a boolean')
    })

    util.repeatIt('random tests', opts.repeat, function () {
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
      }).to.throw(TypeError, 'public key should be a Buffer')
    })

    it('public key length is invalid', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed.slice(1)
        var tweak = util.getTweak()
        secp256k1.publicKeyTweakMul(publicKey, tweak)
      }).to.throw(RangeError, 'public key length is invalid')
    })

    it('public key is invalid (version is 0x01)', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed
        publicKey[0] = 0x01
        var tweak = util.getTweak()
        secp256k1.publicKeyTweakMul(publicKey, tweak)
      }).to.throw(Error, 'the public key could not be parsed or is invalid')
    })

    it('tweak should be a Buffer', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed
        secp256k1.publicKeyTweakMul(publicKey, null)
      }).to.throw(TypeError, 'tweak should be a Buffer')
    })

    it('tweak length is invalid', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed
        var tweak = util.getTweak().slice(1)
        secp256k1.publicKeyTweakMul(publicKey, tweak)
      }).to.throw(RangeError, 'tweak length is invalid')
    })

    it('tweak is zero', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed
        var tweak = new Buffer(util.BN_ZERO.toArray(null, 32))
        secp256k1.publicKeyTweakMul(publicKey, tweak)
      }).to.throw(Error, 'tweak out of range')
    })

    it('tweak overflow', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed
        var tweak = new Buffer(util.ec.curve.n.toArray(null, 32))
        secp256k1.publicKeyTweakMul(publicKey, tweak)
      }).to.throw(Error, 'tweak out of range')
    })

    it('compressed should be a boolean', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed
        var tweak = util.getTweak()
        secp256k1.publicKeyTweakMul(publicKey, tweak, null)
      }).to.throw(TypeError, 'compressed should be a boolean')
    })

    util.repeatIt('random tests', opts.repeat, function () {
      var privateKey = util.getPrivateKey()
      var publicPoint = util.ec.g.mul(new BN(privateKey))
      var publicKey = new Buffer(publicPoint.encode(null, true))
      var tweak = util.getTweak()

      if (new BN(tweak).cmp(util.BN_ZERO) === 0) {
        return expect(function () {
          secp256k1.publicKeyTweakMul(publicKey, tweak)
        }).to.throw(Error, 'tweak out of range')
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
      }).to.throw(TypeError, 'public keys should be an Array')
    })

    it('public keys should have length greater that zero', function () {
      expect(function () {
        secp256k1.publicKeyCombine([])
      }).to.throw(RangeError, 'public keys Array should have at least 1 element')
    })

    it('public key should be a Buffer', function () {
      expect(function () {
        secp256k1.publicKeyCombine([null])
      }).to.throw(TypeError, 'public key should be a Buffer')
    })

    it('public key length is invalid', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed.slice(1)
        secp256k1.publicKeyCombine([publicKey])
      }).to.throw(RangeError, 'public key length is invalid')
    })

    it('public key is invalid (version is 0x01)', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed
        publicKey[0] = 0x01
        secp256k1.publicKeyCombine([publicKey])
      }).to.throw(Error, 'the public key could not be parsed or is invalid')
    })

    it('compressed should be a boolean', function () {
      expect(function () {
        var publicKey = util.getPublicKey().compressed
        secp256k1.publicKeyCombine([publicKey], null)
      }).to.throw(TypeError, 'compressed should be a boolean')
    })

    util.repeatIt('random tests', opts.repeat, function () {
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
