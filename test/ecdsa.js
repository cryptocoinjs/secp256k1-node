'use strict'
/* global describe, it */

var expect = require('chai').expect
var getRandomBytes = require('crypto').randomBytes

var util = require('./util')
var messages = require('../lib/messages')

/**
 * @param {Object} secp256k1
 */
module.exports = function (secp256k1) {
  describe('sign', function () {
    it('message should be a Buffer', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        secp256k1.sign(null, privateKey)
      }).to.throw(TypeError, messages.MSG32_TYPE_INVALID)
    })

    it('message invalid length', function () {
      expect(function () {
        var message = util.getMessage().slice(1)
        var privateKey = util.getPrivateKey()
        secp256k1.sign(message, privateKey)
      }).to.throw(RangeError, messages.MSG32_LENGTH_INVALID)
    })

    it('private key should be a Buffer', function () {
      expect(function () {
        var message = util.getMessage()
        secp256k1.sign(message, null)
      }).to.throw(TypeError, messages.EC_PRIVATE_KEY_TYPE_INVALID)
    })

    it('private key invalid length', function () {
      expect(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey().slice(1)
        secp256k1.sign(message, privateKey)
      }).to.throw(RangeError, messages.EC_PRIVATE_KEY_LENGTH_INVALID)
    })

    it('private key is invalid', function () {
      expect(function () {
        var message = util.getMessage()
        var privateKey = new Buffer(util.ec.n.toArray(null, 32))
        secp256k1.sign(message, privateKey)
      }).to.throw(Error, messages.ECDSA_SIGN_FAIL)
    })

    it('options should be an Object', function () {
      expect(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey()
        secp256k1.sign(message, privateKey, null)
      }).to.throw(TypeError, messages.OPTIONS_TYPE_INVALID)
    })

    it('options.data should be a Buffer', function () {
      expect(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey()
        secp256k1.sign(message, privateKey, {data: null})
      }).to.throw(TypeError, messages.OPTIONS_DATA_TYPE_INVALID)
    })

    it('options.data length is invalid', function () {
      expect(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey()
        var data = getRandomBytes(31)
        secp256k1.sign(message, privateKey, {data: data})
      }).to.throw(RangeError, messages.OPTIONS_DATA_LENGTH_INVALID)
    })

    it('options.noncefn should be a Function', function () {
      expect(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey()
        secp256k1.sign(message, privateKey, {noncefn: null})
      }).to.throw(TypeError, messages.OPTIONS_NONCEFN_TYPE_INVALID)
    })

    it('noncefn return not a Buffer', function () {
      expect(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey()
        var noncefn = function () { return null }
        secp256k1.sign(message, privateKey, {noncefn: noncefn})
      }).to.throw(Error, messages.ECDSA_SIGN_FAIL)
    })

    it('noncefn return Buffer with invalid length', function () {
      expect(function () {
        var message = util.getMessage()
        var privateKey = util.getPrivateKey()
        var noncefn = function () { return getRandomBytes(31) }
        secp256k1.sign(message, privateKey, {noncefn: noncefn})
      }).to.throw(Error, messages.ECDSA_SIGN_FAIL)
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
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(message, privateKey)
        var publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.verify(null, signature, publicKey)
      }).to.throw(TypeError, messages.MSG32_TYPE_INVALID)
    })

    it('message length is invalid', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage().slice(1)
        var signature = util.getSignature(message, privateKey)
        var publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.verify(message, signature, publicKey)
      }).to.throw(RangeError, messages.MSG32_LENGTH_INVALID)
    })

    it('signature should be a Buffer', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.verify(message, null, publicKey)
      }).to.throw(TypeError, messages.ECDSA_SIGNATURE_TYPE_INVALID)
    })

    it('signature length is invalid', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(message, privateKey).slice(1)
        var publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.verify(message, signature, publicKey)
      }).to.throw(RangeError, messages.ECDSA_SIGNATURE_LENGTH_INVALID)
    })

    it('signature is invalid (r equal N)', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = Buffer.concat([
          new Buffer(util.ec.n.toArray(null, 32)),
          getRandomBytes(32)
        ])
        var publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.verify(message, signature, publicKey)
      }).to.throw(Error, messages.ECDSA_SIGNATURE_PARSE_FAIL)
    })

    it('public key should be a Buffer', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(message, privateKey)
        secp256k1.verify(message, signature, null)
      }).to.throw(TypeError, messages.EC_PUBLIC_KEY_TYPE_INVALID)
    })

    it('public key length is invalid', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(message, privateKey)
        var publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        secp256k1.verify(message, signature, publicKey)
      }).to.throw(RangeError, messages.EC_PUBLIC_KEY_LENGTH_INVALID)
    })

    it('public key is invalid (version is 0x01)', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(message, privateKey)
        var publicKey = util.getPublicKey(privateKey).compressed
        publicKey[0] = 0x01
        secp256k1.verify(message, signature, publicKey)
      }).to.throw(Error, messages.EC_PUBLIC_KEY_PARSE_FAIL)
    })
  })

  describe('recover', function () {
    it('message should be a Buffer', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(message, privateKey)
        secp256k1.recover(null, signature, 0)
      }).to.throw(TypeError, messages.MSG32_TYPE_INVALID)
    })

    it('message length is invalid', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage().slice(1)
        var signature = util.getSignature(message, privateKey)
        secp256k1.recover(message, signature, 0)
      }).to.throw(RangeError, messages.MSG32_LENGTH_INVALID)
    })

    it('signature should be a Buffer', function () {
      expect(function () {
        var message = util.getMessage()
        secp256k1.recover(message, null, 0)
      }).to.throw(TypeError, messages.ECDSA_SIGNATURE_TYPE_INVALID)
    })

    it('signature length is invalid', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(message, privateKey).slice(1)
        secp256k1.recover(message, signature, 0)
      }).to.throw(RangeError, messages.ECDSA_SIGNATURE_LENGTH_INVALID)
    })

    it('signature is invalid (r equal N)', function () {
      expect(function () {
        var message = util.getMessage()
        var signature = Buffer.concat([
          new Buffer(util.ec.n.toArray(null, 32)),
          getRandomBytes(32)
        ])
        secp256k1.recover(message, signature, 0)
      }).to.throw(Error, messages.ECDSA_SIGNATURE_PARSE_FAIL)
    })

    it('recovery should be a Number', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(message, privateKey)
        secp256k1.recover(message, signature, null)
      }).to.throw(TypeError, messages.RECOVERY_ID_TYPE_INVALID)
    })

    it('recovery is invalid (equal 4)', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(privateKey, message)
        secp256k1.recover(message, signature, 4)
      }).to.throw(RangeError, messages.RECOVERY_ID_VALUE_INVALID)
    })

    it('compressed should be a boolean', function () {
      expect(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(message, privateKey)
        secp256k1.recover(message, signature, 0, null)
      }).to.throw(TypeError, messages.COMPRESSED_TYPE_INVALID)
    })
  })

  describe('sign/verify/recover', function () {
    util.repeatIt('random tests', util.env.repeat, function () {
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
