var expect = require('chai').expect
var ECKey = require('eckey')

var util = require('./util')

/**
 * @param {Object} secp256k1
 * @param {Object} opts
 * @param {number} opts.repeat
 */
module.exports = function (secp256k1, opts) {
  describe('sign/verify/recovery', function () {
    util.repeatIt('random tests', opts.repeat, function () {
      var msg = util.getMessage()
      var eckey = new ECKey(util.getPrivateKey())
      var expected = util.signSync(msg, eckey.privateKey)

      var sigObj

      return secp256k1.sign(msg, eckey.privateKey)
        .then(function (value) {
          sigObj = value
          expect(sigObj.signature.toString('hex')).to.equal(expected.signatureLowS.toString('hex'))

          return secp256k1.verify(msg, sigObj.signature, eckey.publicKey)
        })
        .then(function (value) {
          expect(value).to.be.true

          return secp256k1.recover(msg, sigObj.signature, sigObj.recovery)
        })
        .then(function (value) {
          expect(value.toString('hex')).to.equal(eckey.publicKey.toString('hex'))
        })
    })
  })

  describe('signSync/verifySync/recoverSync', function () {
    util.repeatIt('random tests', opts.repeat, function () {
      var msg = util.getMessage()
      var eckey = new ECKey(util.getPrivateKey())
      var expected = util.signSync(msg, eckey.privateKey)

      var sigObj = secp256k1.signSync(msg, eckey.privateKey)
      expect(sigObj.signature.toString('hex')).to.equal(expected.signatureLowS.toString('hex'))

      var result = secp256k1.verifySync(msg, sigObj.signature, eckey.publicKey)
      expect(result).to.be.true

      var publicKey = secp256k1.recoverSync(msg, sigObj.signature, sigObj.recovery)
      expect(publicKey.toString('hex')).to.equal(eckey.publicKey.toString('hex'))
    })
  })
}
