var expect = require('chai').expect
var BigInteger = require('bigi')

var util = require('./util')

/**
 * @param {Object} secp256k1
 * @param {Object} opts
 * @param {number} opts.repeat
 */
module.exports = function (secp256k1, opts) {
  describe('secretKeyVerify', function () {
    it('should be a Buffer', function () {
      expect(function () {
        secp256k1.secretKeyVerify(null)
      }).to.throw(TypeError, /secret/)
    })

    it('invalid length', function () {
      expect(secp256k1.secretKeyVerify(util.getPrivateKey().slice(1))).to.be.false
    })

    it('zero key', function () {
      var privKey = BigInteger.ZERO.toBuffer(32)
      expect(secp256k1.secretKeyVerify(privKey)).to.be.false
    })

    it('equal to N', function () {
      var privKey = util.ecparams.n.toBuffer(32)
      expect(secp256k1.secretKeyVerify(privKey)).to.be.false
    })

    util.repeatIt('random tests', opts.repeat, function () {
      var privKey = util.getPrivateKey()
      expect(secp256k1.secretKeyVerify(privKey)).to.be.true
    })
  })

  describe('secretKeyExport', function () {
    it('secret key should be a Buffer', function () {
      expect(function () {
        secp256k1.secretKeyExport(null)
      }).to.throw(TypeError, /secret/)
    })

    it('compressed should be a boolean', function () {
      expect(function () {
        secp256k1.secretKeyExport(util.getPrivateKey(), null)
      }).to.throw(TypeError, /compressed/)
    })

    it('secret key length is invalid', function () {
      expect(function () {
        secp256k1.secretKeyExport(util.getPrivateKey().slice(1))
      }).to.throw(RangeError, /secret/)
    })

    it('secret key is invalid', function () {
      expect(function () {
        secp256k1.secretKeyExport(util.ecparams.n.toBuffer(32))
      }).to.throw(Error)
    })
  })

  describe('secretKeyImport', function () {
    it('should be a Buffer', function () {
      expect(function () {
        secp256k1.secretKeyImport(null)
      }).to.throw(TypeError, /secret/)
    })

    it('invalid format', function () {
      expect(function () {
        secp256k1.secretKeyImport(new Buffer([0x00]))
      }).to.throw(Error)
    })
  })

  describe('secretKeyExport/secretKeyImport', function () {
    util.repeatIt('random tests', opts.repeat, function () {
      var privKey = util.getPrivateKey()

      var der1 = secp256k1.secretKeyExport(privKey, true)
      var privKey1 = secp256k1.secretKeyImport(der1)
      expect(privKey1.toString('hex')).to.equal(privKey.toString('hex'))

      var der2 = secp256k1.secretKeyExport(privKey, false)
      var privKey2 = secp256k1.secretKeyImport(der2)
      expect(privKey2.toString('hex')).to.equal(privKey.toString('hex'))
    })
  })

  describe('secretKeyTweakAdd', function () {
    it('secret key should be a Buffer', function () {
      expect(function () {
        secp256k1.secretKeyTweakAdd(null, util.getTweak())
      }).to.throw(TypeError, /secret/)
    })

    it('tweak should be a Buffer', function () {
      expect(function () {
        secp256k1.secretKeyTweakAdd(util.getPrivateKey(), null)
      }).to.throw(TypeError, /tweak/)
    })

    it('secret key length is invalid', function () {
      expect(function () {
        secp256k1.secretKeyTweakAdd(util.getPrivateKey().slice(1), util.getTweak())
      }).to.throw(RangeError, /secret/)
    })

    it('tweak length is invalid', function () {
      expect(function () {
        secp256k1.secretKeyTweakAdd(util.getPrivateKey(), util.getTweak().slice(1))
      }).to.throw(RangeError, /tweak/)
    })

    it('tweak overflow', function () {
      expect(function () {
        secp256k1.secretKeyTweakAdd(util.getPrivateKey(), util.ecparams.n.toBuffer(32))
      }).to.throw(Error, /range/)
    })

    it('throw Error (result is zero: (N - 1) + 1)', function () {
      expect(function () {
        var privKey = util.ecparams.n.subtract(BigInteger.ONE).toBuffer(32)
        secp256k1.secretKeyTweakAdd(privKey, BigInteger.ONE.toBuffer(32))
      }).to.throw(Error, /range/)
    })

    util.repeatIt('random tests', opts.repeat, function () {
      var privKey = util.getPrivateKey()
      var tweak = util.getTweak()

      var expected = BigInteger.fromBuffer(privKey).add(BigInteger.fromBuffer(tweak))
      if (expected.compareTo(util.ecparams.n) >= 0) {
        expected = expected.subtract(util.ecparams.n)
      }

      if (expected.compareTo(BigInteger.ZERO) === 0) {
        return expect(function () {
          secp256k1.secretKeyTweakAdd(privKey, tweak)
        }).to.throw(Error, /range/)
      }

      var result = secp256k1.secretKeyTweakAdd(privKey, tweak)
      expect(result.toString('hex')).to.equal(expected.toHex(32))
    })
  })

  describe('secretKeyTweakMul', function () {
    it('secret key should be a Buffer', function () {
      expect(function () {
        secp256k1.secretKeyTweakMul(null, util.getTweak())
      }).to.throw(TypeError, /secret/)
    })

    it('tweak should be a Buffer', function () {
      expect(function () {
        secp256k1.secretKeyTweakMul(util.getPrivateKey(), null)
      }).to.throw(TypeError, /tweak/)
    })

    it('secret key length is invalid', function () {
      expect(function () {
        secp256k1.secretKeyTweakMul(util.getPrivateKey().slice(1), util.getTweak())
      }).to.throw(RangeError, /secret/)
    })

    it('tweak length is invalid', function () {
      expect(function () {
        secp256k1.secretKeyTweakMul(util.getPrivateKey(), util.getTweak().slice(1))
      }).to.throw(RangeError, /tweak/)
    })

    it('throw Error (tweak is 0)', function () {
      expect(function () {
        var privKey = util.getPrivateKey()
        secp256k1.secretKeyTweakMul(privKey, BigInteger.ZERO.toBuffer(32))
      }).to.throw(Error, /range/)
    })

    util.repeatIt('random tests', opts.repeat, function () {
      var privKey = util.getPrivateKey()
      var tweak = util.getTweak()

      if (BigInteger.fromBuffer(tweak).compareTo(BigInteger.ZERO) === 0) {
        return expect(function () {
          secp256k1.secretKeyTweakMul(privKey, tweak)
        }).to.throw(Error, /range/)
      }

      var expected = BigInteger.fromBuffer(privKey)
        .multiply(BigInteger.fromBuffer(tweak))
        .remainder(util.ecparams.n)

      var result = secp256k1.secretKeyTweakMul(privKey, tweak)
      expect(result.toString('hex')).to.equal(expected.toHex(32))
    })
  })
}
