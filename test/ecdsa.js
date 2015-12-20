'use strict'

var expect = require('chai').expect
var getRandomBytes = require('crypto').randomBytes

var util = require('./util')

/**
 * @param {Object} secp256k1
 * @param {Object} opts
 * @param {number} opts.repeat
 */
module.exports = function (secp256k1, opts) {
  describe('sign', function () {
    it('message should be a Buffer', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        secp256k1.sign(null, privateKey)
      }).to.throw(TypeError, 'message should be a Buffer')
    })

    it('message invalid length', function () {
      expect(function () {
        var message = util.getMessage().slice(1)
        var privateKey = util.getPrivateKey()
        secp256k1.sign(message, privateKey)
      }).to.throw(RangeError, 'message length is invalid')
    })

    it('private key should be a Buffer', function () {
      expect(function () {
        var message = util.getMessage()
        secp256k1.sign(message, null)
      }).to.throw(TypeError, 'private key should be a Buffer')
    })

    it('private key invalid length', function () {
      expect(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey().slice(1)
        secp256k1.sign(message, privateKey)
      }).to.throw(RangeError, 'private key length is invalid')
    })

    it('private key is invalid', function () {
      expect(function () {
        var message = util.getMessage()
        var privateKey = new Buffer(util.ec.n.toArray(null, 32))
        secp256k1.sign(message, privateKey)
      }).to.throw(Error, 'nonce generation function failed or private key is invalid')
    })

    it('options should be an Object', function () {
      expect(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey()
        secp256k1.sign(message, privateKey, null)
      }).to.throw(TypeError, 'options should be an Object')
    })

    it('options.data should be a Buffer', function () {
      expect(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey()
        secp256k1.sign(message, privateKey, {data: null})
      }).to.throw(TypeError, 'options.data should be a Buffer')
    })

    it('options.data length is invalid', function () {
      expect(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey()
        var data = getRandomBytes(31)
        secp256k1.sign(message, privateKey, {data: data})
      }).to.throw(RangeError, 'options.data length is invalid')
    })

    it('options.noncefn should be a Function', function () {
      expect(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey()
        secp256k1.sign(message, privateKey, {noncefn: null})
      }).to.throw(TypeError, 'options.noncefn should be a Function')
    })

    it('noncefn return not a Buffer', function () {
      expect(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey()
        var noncefn = function () { return null }
        secp256k1.sign(message, privateKey, {noncefn: noncefn})
      }).to.throw(Error, 'nonce generation function failed or private key is invalid')
    })

    it('noncefn return Buffer with invalid length', function () {
      expect(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey()
        var noncefn = function () { return getRandomBytes(31) }
        secp256k1.sign(message, privateKey, {noncefn: noncefn})
      }).to.throw(Error, 'nonce generation function failed or private key is invalid')
    })

    it('check options.noncefn arguments', function (done) {
      var message = util.getMessage()
      var privateKey = util.getPrivateKey()
      var data = getRandomBytes(32)
      var noncefn = function (message2, privateKey2, algo, data2, attempt) {
        try {
          expect(message2.toString('hex')).to.equal(message.toString('hex'))
          expect(privateKey.toString('hex')).to.equal(privateKey.toString('hex'))
          expect(algo).to.be.null
          expect(data2.toString('hex')).to.equal(data.toString('hex'))
          expect(attempt).to.be.a('number').and.to.equal(0)
          done()
        } catch (err) {
          done(err)
        } finally {
          return getRandomBytes(32)
        }
      }
      secp256k1.sign(message, privateKey, {data: data, noncefn: noncefn})
    })
  })

  describe('verify', function () {
    it('message should be a Buffer', function () {
      expect(function () {
        var signature = util.getSignature()
        var publicKey = util.getPublicKey().compressed
        secp256k1.verify(null, signature, publicKey)
      }).to.throw(TypeError, 'message should be a Buffer')
    })

    it('message length is invalid', function () {
      expect(function () {
        var message = util.getMessage().slice(1)
        var signature = util.getSignature()
        var publicKey = util.getPublicKey().compressed
        secp256k1.verify(message, signature, publicKey)
      }).to.throw(RangeError, 'message length is invalid')
    })

    it('signature should be a Buffer', function () {
      expect(function () {
        var message = util.getMessage()
        var publicKey = util.getPublicKey().compressed
        secp256k1.verify(message, null, publicKey)
      }).to.throw(TypeError, 'signature should be a Buffer')
    })

    it('signature length is invalid', function () {
      expect(function () {
        var message = util.getMessage()
        var signature = util.getSignature().slice(1)
        var publicKey = util.getPublicKey().compressed
        secp256k1.verify(message, signature, publicKey)
      }).to.throw(RangeError, 'signature length is invalid')
    })

    it('signature is invalid (r equal N)', function () {
      expect(function () {
        var message = util.getMessage()
        var signature = Buffer.concat([
          new Buffer(util.ec.n.toArray(null, 32)),
          getRandomBytes(32)
        ])
        var publicKey = util.getPublicKey().compressed
        secp256k1.verify(message, signature, publicKey)
      }).to.throw(Error, 'couldn\'t parse signature')
    })

    it('public key should be a Buffer', function () {
      expect(function () {
        var message = util.getMessage()
        var signature = util.getSignature()
        secp256k1.verify(message, signature, null)
      }).to.throw(TypeError, 'public key should be a Buffer')
    })

    it('public key length is invalid', function () {
      expect(function () {
        var message = util.getMessage()
        var signature = util.getSignature()
        var publicKey = util.getPublicKey().compressed.slice(1)
        secp256k1.verify(message, signature, publicKey)
      }).to.throw(RangeError, 'public key length is invalid')
    })

    it('public key is invalid (version is 0x01)', function () {
      expect(function () {
        var message = util.getMessage()
        var signature = util.getSignature()
        var publicKey = util.getPublicKey().compressed
        publicKey[0] = 0x01
        secp256k1.verify(message, signature, publicKey)
      }).to.throw(Error, 'the public key could not be parsed or is invalid')
    })
  })

  describe('recover', function () {
    it('message should be a Buffer', function () {
      expect(function () {
        var signature = util.getSignature()
        secp256k1.recover(null, signature, 0)
      }).to.throw(TypeError, 'message should be a Buffer')
    })

    it('message length is invalid', function () {
      expect(function () {
        var message = util.getMessage().slice(1)
        var signature = util.getSignature()
        secp256k1.recover(message, signature, 0)
      }).to.throw(RangeError, 'message length is invalid')
    })

    it('signature should be a Buffer', function () {
      expect(function () {
        var message = util.getMessage()
        secp256k1.recover(message, null, 0)
      }).to.throw(TypeError, 'signature should be a Buffer')
    })

    it('signature length is invalid', function () {
      expect(function () {
        var message = util.getMessage()
        var signature = util.getSignature().slice(1)
        secp256k1.recover(message, signature, 0)
      }).to.throw(RangeError, 'signature length is invalid')
    })

    it('signature is invalid (r equal N)', function () {
      expect(function () {
        var message = util.getMessage()
        var signature = Buffer.concat([
          new Buffer(util.ec.n.toArray(null, 32)),
          getRandomBytes(32)
        ])
        secp256k1.recover(message, signature, 0)
      }).to.throw(Error, 'couldn\'t parse signature')
    })

    it('recovery should be a Number', function () {
      expect(function () {
        var message = util.getMessage()
        var signature = util.getSignature()
        secp256k1.recover(message, signature, null)
      }).to.throw(TypeError, 'recovery should be a Number')
    })

    it('recovery is invalid (equal 4)', function () {
      expect(function () {
        var message = util.getMessage()
        var signature = util.getSignature()
        secp256k1.recover(message, signature, 4)
      }).to.throw(RangeError, 'recovery should have value between -1 and 4')
    })

    it('compressed should be a boolean', function () {
      expect(function () {
        var message = util.getMessage()
        var signature = util.getSignature()
        secp256k1.recover(message, signature, 0, null)
      }).to.throw(TypeError, 'compressed should be a boolean')
    })
  })

  describe('sign/verify/recover', function () {
    util.repeatIt('random tests', opts.repeat, function () {
      var message = util.getMessage()
      var privateKey = util.getPrivateKey()
      var publicKey = util.getPublicKey(privateKey)
      var expected = util.sign(message, privateKey)

      var sigObj = secp256k1.sign(message, privateKey)
      expect(sigObj.signature.toString('hex')).to.equal(expected.signatureLowS.toString('hex'))
      expect(sigObj.recovery).to.equal(expected.recovery)

      var isValid = secp256k1.verify(message, sigObj.signature, publicKey.compressed)
      expect(isValid).to.be.true

      var compressed = secp256k1.recover(message, sigObj.signature, sigObj.recovery, true)
      expect(compressed.toString('hex')).to.equal(publicKey.compressed.toString('hex'))

      var uncompressed = secp256k1.recover(message, sigObj.signature, sigObj.recovery, false)
      expect(uncompressed.toString('hex')).to.equal(publicKey.uncompressed.toString('hex'))
    })
  })
}
