var expect = require('chai').expect
var BigInteger = require('bigi')

var SECP256K1_N = require('./const').SECP256K1_N
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
      var privKey = SECP256K1_N.toBuffer(32)
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
        secp256k1.secretKeyExport(SECP256K1_N.toBuffer(32))
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
      var der2 = secp256k1.secretKeyExport(privKey, true)
      expect(secp256k1.secretKeyImport(der2).toString('hex')).to.equal(privKey.toString('hex'))
      var der1 = secp256k1.secretKeyExport(privKey, false)
      expect(secp256k1.secretKeyImport(der1).toString('hex')).to.equal(privKey.toString('hex'))
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

    it('throw Error (overflow: (N - 1) + 1)', function () {
      expect(function () {
        var privKey = SECP256K1_N.subtract(BigInteger.ONE).toBuffer(32)
        secp256k1.secretKeyTweakAdd(privKey, BigInteger.ONE.toBuffer(32))
      }).to.throw(Error)
    })

    util.repeatIt.skip('random tests', opts.repeat, function () {
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
      }).to.throw(Error)
    })

    util.repeatIt.skip('random tests', opts.repeat, function () {
    })
  })
}
