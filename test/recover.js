var expect = require('chai').expect
var randomBytes = require('crypto').randomBytes

var util = require('./util')

/**
 * @param {Object} secp256k1
 * @param {Object} opts
 * @param {number} opts.repeat
 */
module.exports = function (secp256k1, opts) {
  describe('recover', function () {
    it('return a Promise', function () {
      expect(secp256k1.recover()).to.be.instanceof(secp256k1.Promise)
    })

    it('callback should be a function', function () {
      expect(function () {
        secp256k1.recover(util.getMessage(), util.getPrivateKey(), 0, null)
      }).to.throw(TypeError)
    })

    it('message should be a Buffer', function () {
      var promise = secp256k1.recover(null, util.getSignature(), 0)
      return expect(promise).to.be.rejectedWith(TypeError, /message/)
    })

    it('signature should be a Buffer', function () {
      var promise = secp256k1.recover(util.getMessage(), null, 0)
      return expect(promise).to.be.rejectedWith(TypeError, /signature/)
    })

    it('recovery should be a Number', function () {
      var promise = secp256k1.recover(util.getMessage(), util.getSignature(), null)
      return expect(promise).to.be.rejectedWith(TypeError, /recovery/)
    })

    it('message length is invalid', function () {
      var promise = secp256k1.recover(util.getMessage().slice(1), util.getSignature(), 0)
      return expect(promise).to.be.rejectedWith(RangeError, /message/)
    })

    it('signature length is invalid', function () {
      var promise = secp256k1.recover(util.getMessage(), util.getSignature().slice(1), 0)
      return expect(promise).to.be.rejectedWith(RangeError, /signature/)
    })

    it('recovery is invalid (equal 4)', function () {
      var promise = secp256k1.recover(util.getMessage(), util.getSignature(), 4)
      return expect(promise).to.be.rejectedWith(RangeError, /recovery/)
    })

    it('recovery is invalid (equal 32 bytes+)', function () {
      var promise = secp256k1.recover(util.getMessage(), util.getSignature(), 57779999999999999999999999999999999999999999999)
      return expect(promise).to.be.rejectedWith(RangeError, /recovery/)
    })

    it('signature is invalid (r equal N)', function () {
      var signature = Buffer.concat([
        util.ecparams.n.toBuffer(32),
        randomBytes(32)
      ])
      var promise = secp256k1.recover(util.getMessage(), signature, 0)
      return expect(promise).to.be.rejectedWith(Error, /signature/)
    })
  })

  describe('recoverSync', function () {
    it('message should be a Buffer', function () {
      expect(function () {
        secp256k1.recoverSync(null, util.getSignature(), 0)
      }).to.throw(TypeError, /message/)
    })

    it('signature should be a Buffer', function () {
      expect(function () {
        secp256k1.recoverSync(util.getMessage(), null, 0)
      }).to.throw(TypeError, /signature/)
    })

    it('recovery should be a Number', function () {
      expect(function () {
        secp256k1.recoverSync(util.getMessage(), util.getSignature(), null)
      }).to.throw(TypeError, /recovery/)
    })

    it('message length is invalid', function () {
      expect(function () {
        secp256k1.recoverSync(util.getMessage().slice(1), util.getSignature(), 0)
      }).to.throw(RangeError, /message/)
    })

    it('signature length is invalid', function () {
      expect(function () {
        secp256k1.recoverSync(util.getMessage(), util.getSignature().slice(1), 0)
      }).to.throw(RangeError, /signature/)
    })

    it('recovery is invalid (equal 4)', function () {
      expect(function () {
        secp256k1.recoverSync(util.getMessage(), util.getSignature(), 4)
      }).to.throw(RangeError, /recovery/)
    })

    it('signature is invalid (r equal N)', function () {
      expect(function () {
        var signature = Buffer.concat([
          util.ecparams.n.toBuffer(32),
          randomBytes(32)
        ])
        secp256k1.recoverSync(util.getMessage(), signature, 0)
      }).to.throw(Error, /signature/)
    })

    it('failed invalid signature testcase', function () {
      expect(function () {
        var msg = new Buffer('82ff40c0a986c6a5cfad4ddf4c3aa6996f1a7837f9c398e17e5de5cbd5a12b28', 'hex')
        var signature = new Buffer('129ff05af364204442bdb53ab6f18a99ab48acc9326fa689f228040429e3ca6699e71a99cb2270b8cac5254f9e99b6210c6c10224a1579cf389ef88b20a1abe9', 'hex')
        secp256k1.recoverSync(msg, signature, 0)
      }).to.throw(Error, /signature/)
    })
  })
}
