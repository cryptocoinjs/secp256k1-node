var getRandomBytes = require('crypto').randomBytes
var BN = require('bn.js')
var ECKey = require('eckey')

var secp256k1 = require('../js')

var ZERO = new BN(0)
var N = new BN('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', 'hex')

/**
 * @return {Buffer}
 */
exports.generateKeyPair = function () {
  while (true) {
    var privateKey = getRandomBytes(32)
    var bn = new BN(privateKey)
    if (bn.cmp(ZERO) !== 0 && bn.cmp(N) < 0) {
      var eckey = new ECKey(privateKey)
      return {
        privateKey: privateKey,
        publicKey: eckey.publicKey
      }
    }
  }
}

/**
 * @return {Buffer}
 */
exports.getMessage = function () {
  return getRandomBytes(32)
}

/**
 * @param {Buffer} message
 * @param {Buffer} privateKey
 * @return {Buffer}
 */
exports.createSignature = function (message, privateKey) {
  return secp256k1.signSync(message, privateKey).signature
}
