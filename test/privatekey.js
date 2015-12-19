var expect = require('chai').expect
var BN = require('bn.js')

var util = require('./util')

/**
 * @param {Object} secp256k1
 * @param {Object} opts
 * @param {number} opts.repeat
 */
module.exports = function (secp256k1, opts) {
  describe('privateKeyVerify', function () {
    it('should be a Buffer', function () {
      expect(function () {
        secp256k1.privateKeyVerify(null)
      }).to.throw(TypeError, 'private key should be a Buffer')
    })

    it('invalid length', function () {
      var privateKey = util.getPrivateKey().slice(1)
      expect(secp256k1.privateKeyVerify(privateKey)).to.be.false
    })

    it('zero key', function () {
      var privateKey = new Buffer(util.BN_ZERO.toArray(null, 32))
      expect(secp256k1.privateKeyVerify(privateKey)).to.be.false
    })

    it('equal to N', function () {
      var privateKey = new Buffer(util.ec.curve.n.toArray(null, 32))
      expect(secp256k1.privateKeyVerify(privateKey)).to.be.false
    })

    util.repeatIt('random tests', opts.repeat, function () {
      var privateKey = util.getPrivateKey()
      expect(secp256k1.privateKeyVerify(privateKey)).to.be.true
    })
  })

  describe('privateKeyExport', function () {
    it('private key should be a Buffer', function () {
      expect(function () {
        secp256k1.privateKeyExport(null)
      }).to.throw(TypeError, 'private key should be a Buffer')
    })

    it('private key length is invalid', function () {
      expect(function () {
        var privateKey = util.getPrivateKey().slice(1)
        secp256k1.privateKeyExport(privateKey)
      }).to.throw(RangeError, 'private key length is invalid')
    })

    it('compressed should be a boolean', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        secp256k1.privateKeyExport(privateKey, null)
      }).to.throw(TypeError, 'compressed should be a boolean')
    })

    it('private key is invalid', function () {
      expect(function () {
        var privateKey = new Buffer(util.ec.curve.n.toArray(null, 32))
        secp256k1.privateKeyExport(privateKey)
      }).to.throw(Error, 'couldn\'t export to DER format')
    })
  })

  describe('privateKeyImport', function () {
    it('should be a Buffer', function () {
      expect(function () {
        secp256k1.privateKeyImport(null)
      }).to.throw(TypeError, 'private key should be a Buffer')
    })

    it('invalid format', function () {
      expect(function () {
        var buffer = new Buffer([0x00])
        secp256k1.privateKeyImport(buffer)
      }).to.throw(Error, 'couldn\'t import from DER format')
    })
  })

  describe('privateKeyExport/privateKeyImport', function () {
    util.repeatIt('random tests', opts.repeat, function () {
      var privateKey = util.getPrivateKey()

      var der1 = secp256k1.privateKeyExport(privateKey, true)
      var privateKey1 = secp256k1.privateKeyImport(der1)
      expect(privateKey1.toString('hex')).to.equal(privateKey.toString('hex'))

      var der2 = secp256k1.privateKeyExport(privateKey, false)
      var privateKey2 = secp256k1.privateKeyImport(der2)
      expect(privateKey2.toString('hex')).to.equal(privateKey.toString('hex'))
    })
  })

  describe('privateKeyTweakAdd', function () {
    it('private key should be a Buffer', function () {
      expect(function () {
        var tweak = util.getTweak()
        secp256k1.privateKeyTweakAdd(null, tweak)
      }).to.throw(TypeError, 'private key should be a Buffer')
    })

    it('private key length is invalid', function () {
      expect(function () {
        var privateKey = util.getPrivateKey().slice(1)
        var tweak = util.getTweak()
        secp256k1.privateKeyTweakAdd(privateKey, tweak)
      }).to.throw(RangeError, 'private key length is invalid')
    })

    it('tweak should be a Buffer', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        secp256k1.privateKeyTweakAdd(privateKey, null)
      }).to.throw(TypeError, 'tweak should be a Buffer')
    })

    it('tweak length is invalid', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var tweak = util.getTweak().slice(1)
        secp256k1.privateKeyTweakAdd(privateKey, tweak)
      }).to.throw(RangeError, 'tweak length is invalid')
    })

    it('tweak overflow', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var tweak = new Buffer(util.ec.curve.n.toArray(null, 32))
        secp256k1.privateKeyTweakAdd(privateKey, tweak)
      }).to.throw(Error, 'tweak out of range or resulting private key is invalid')
    })

    it('throw Error (result is zero: (N - 1) + 1)', function () {
      expect(function () {
        var privateKey = new Buffer(util.ec.curve.n.sub(util.BN_ONE).toArray(null, 32))
        var tweak = new Buffer(util.BN_ONE.toArray(null, 32))
        secp256k1.privateKeyTweakAdd(privateKey, tweak)
      }).to.throw(Error, 'tweak out of range or resulting private key is invalid')
    })

    util.repeatIt('random tests', opts.repeat, function () {
      var privateKey = util.getPrivateKey()
      var tweak = util.getTweak()

      var expected = new BN(privateKey).add(new BN(tweak)).mod(util.ec.curve.n)
      if (expected.cmp(util.BN_ZERO) === 0) {
        return expect(function () {
          secp256k1.privateKeyTweakAdd(privateKey, tweak)
        }).to.throw(Error, 'tweak out of range or resulting private key is invalid')
      }

      var result = secp256k1.privateKeyTweakAdd(privateKey, tweak)
      expect(result.toString('hex')).to.equal(expected.toString(16, 64))
    })
  })

  describe('privateKeyTweakMul', function () {
    it('private key should be a Buffer', function () {
      expect(function () {
        var tweak = util.getTweak()
        secp256k1.privateKeyTweakMul(null, tweak)
      }).to.throw(TypeError, 'private key should be a Buffer')
    })

    it('private key length is invalid', function () {
      expect(function () {
        var privateKey = util.getPrivateKey().slice(1)
        var tweak = util.getTweak()
        secp256k1.privateKeyTweakMul(privateKey, tweak)
      }).to.throw(RangeError, 'private key length is invalid')
    })

    it('tweak should be a Buffer', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        secp256k1.privateKeyTweakMul(privateKey, null)
      }).to.throw(TypeError, 'tweak should be a Buffer')
    })

    it('tweak length is invalid', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var tweak = util.getTweak().slice(1)
        secp256k1.privateKeyTweakMul(privateKey, tweak)
      }).to.throw(RangeError, 'tweak length is invalid')
    })

    it('throw Error (tweak is 0)', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var tweak = new Buffer(util.BN_ZERO.toArray(null, 32))
        secp256k1.privateKeyTweakMul(privateKey, tweak)
      }).to.throw(Error, 'tweak out of range')
    })

    util.repeatIt('random tests', opts.repeat, function () {
      var privateKey = util.getPrivateKey()
      var tweak = util.getTweak()

      if (new BN(tweak).cmp(util.BN_ZERO) === 0) {
        return expect(function () {
          secp256k1.privateKeyTweakMul(privateKey, tweak)
        }).to.throw(Error, 'tweak out of range')
      }

      var expected = new BN(privateKey).mul(new BN(tweak)).mod(util.ec.curve.n)
      var result = secp256k1.privateKeyTweakMul(privateKey, tweak)
      expect(result.toString('hex')).to.equal(expected.toString(16, 64))
    })
  })
}