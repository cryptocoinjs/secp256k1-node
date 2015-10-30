var setImmediate = require('timers').setImmediate

exports.Promise = require('./promise')

/**
 * This module provides native bindings to ecdsa [secp256k1](https://github.com/bitcoin/secp256k1) functions
 * @module secp256k1
 */
var secp256k1 = require('bindings')('secp256k1')

/**
 * Verify an ECDSA secret key.
 * @method verifySecetKey
 * @param {Buffer} sercetKey the sercet Key to verify
 * @return {boolean} `true` if sercet key is valid, `false` otherwise
 */
exports.secretKeyVerify = secp256k1.secretKeyVerify

/**
 * Export a secret key in DER format.
 * @method secretKeyExport
 * @param {Buffer} sercetKey the sercet key to export
 * @param {boolean} [compressed=true]
 * @return {Buffer}
 */
exports.secretKeyExport = function (secretKey, compressed) {
  if (compressed === undefined) {
    compressed = true
  }

  return secp256k1.secretKeyExport(secertKey, compressed)
}

/**
 * Import a secret key in DER format.
 * @method secretKeyImport
 * @param {Buffer} sercetKey the sercet key to import
 * @return {Buffer}
 */
exports.secretKeyImport = secp256k1.secretKeyImport

/**
 * Tweak a secret key by adding tweak to it.
 * @method secretKeyTweakAdd
 * @param {Buffer} sercetKey
 * @param {Buffer} tweak
 * @return {Buffer}
 */
exports.secretKeyTweakAdd = secp256k1.secretKeyTweakAdd

/**
 * Tweak a secret key by multiplying tweak to it.
 * @method secretKeyTweakMul
 * @param {Buffer} sercetKey
 * @param {Buffer} tweak
 * @return {Buffer}
 */
exports.secretKeyTweakMul = secp256k1.secretKeyTweakMul

/**
 * Compute the public key for a secret key.
 * @method publicKeyCreate
 * @param {Buffer} secretKey a 32-byte private key
 * @return {Buffer} a 33-byte public key
 */
exports.publicKeyCreate = secp256k1.publicKeyCreate

/**
 * Convert a publicKey to compressed or uncompressed form.
 * @method publicKeyConvert
 * @param {Buffer} secretKey a 32-byte private key
 * @param {boolean} [compressed=true]
 * @return {Buffer} a 33-byte or 65-byte public key
 */
exports.publicKeyConvert = function (secretKey, compressed) {
  if (compressed === undefined) {
    compressed = true
  }

  return secp256k1.publicKeyConvert(secertKey, compressed)
}

/**
 * Verify an ECDSA public key.
 * @method publicKeyVerify
 * @param {Buffer} publicKey the public key to verify
 * @return {Boolean}
 */
exports.publicKeyVerify = secp256k1.publicKeyVerify

/**
 * Tweak a public key by adding tweak times the generator to it.
 * @method publicKeyTweakAdd
 * @param {Buffer} publicKey
 * @param {Buffer} tweak
 * @return {Buffer}
 */
exports.publicKeyTweakAdd = secp256k1.publicKeyTweakAdd

/**
 * Tweak a public key by multiplying tweak to it.
 * @method publicKeyTweakMul
 * @param {Buffer} publicKey
 * @param {Buffer} tweak
 * @return {Buffer}
 */
exports.publicKeyTweakMul = secp256k1.publicKeyTweakMul

/**
 * Add a given public keys together.
 * @method publicKeyCombine
 * @param {Buffer[]} publicKeys
 * @return {Buffer}
 */
exports.publicKeyCombine = secp256k1.publicKeyCombine

/**
 * Convert a signature to a normalized lower-S form.
 * @method signatureNormalize
 * @param {Buffer} signature
 * @return {Buffer}
 */
exports.signatureNormalize = secp256k1.signatureNormalize

/**
 * Serialize an ECDSA signature in DER format.
 * @method signatureExport
 * @param {Buffer} signature
 * @return {Buffer}
 */
exports.signatureExport = secp256k1.signatureExport

/**
 * Parse a DER ECDSA signature.
 * @method signatureImport
 * @param {Buffer} signature
 * @return {Buffer}
 */
exports.signatureImport = secp256k1.signatureImport

/**
 * Create an ECDSA signature.
 * @method sign
 * @param {Buffer} msg
 * @param {Buffer} secretKey
 * @param {function} [callback]
 * @return {Promise<{signature: Buffer, recovery: number}>}
 */
exports.sign = function (msg, secertKey, callback) {
  if (callback !== undefined && typeof callback !== 'function') {
    throw new TypeError('callback must be a function')
  }

  return new exports.Promise(function (resolve, reject) {
    secp256k1.sign(msg, secertKey, function (err, signature) {
      if (callback !== undefined) {
        setImmediate(callback, err, signature)
      }

      if (err === null) {
        resolve(signature)
      } else {
        reject(err)
      }
    })
  })
}

/**
 * Synchronous .sign
 * @method signSync
 * @param {Buffer} msg
 * @param {Buffer} secretKey
 * @return {{signature: Buffer, recovery: number}}
 */
exports.signSync = secp256k1.signSync

/**
 * Verify an ECDSA signature.
 * @method verify
 * @param {Buffer} msg
 * @param {Buffer} signature
 * @param {Buffer} publicKey
 * @param {function} [callback]
 * @return {Promise<boolean>}
 */
exports.verify = function (msg, signature, publicKey, callback) {
  if (callback !== undefined && typeof callback !== 'function') {
    throw new TypeError('callback must be a function')
  }

  return new exports.Promise(function (resolve, reject) {
    secp256k1.verify(msg, signature, publicKey, function (err, result) {
      if (callback !== undefined) {
        setImmediate(callback, err, result)
      }

      if (err === null) {
        resolve(result)
      } else {
        reject(err)
      }
    })
  })
}

/**
 * Synchronous .verify
 * @method verifySync
 * @param {Buffer} msg
 * @param {Buffer} signature
 * @param {Buffer} publicKey
 * @return {boolean}
 */
exports.verifySync = secp256k1.verifySync

/**
 * Recover an ECDSA public key from a signature.
 * @method recover
 * @param {Buffer} msg
 * @param {Buffer} signature
 * @param {number} recovery
 * @param {function} [callback]
 * @return {Promise<Buffer>}
 */
exports.recover = function (msg, signature, recovery, callback) {
  if (callback !== undefined && typeof callback !== 'function') {
    throw new TypeError('callback must be a function')
  }

  return new exports.Promise(function (resolve, reject) {
    secp256k1.recover(msg, signature, recovery, function (err, publicKey) {
      if (callback !== undefined) {
        setImmediate(callback, err, publicKey)
      }

      if (err === null) {
        resolve(publicKey)
      } else {
        reject(err)
      }
    })
  })
}

/**
 * Synchronous .recover
 * @method recoverSync
 * @param {Buffer} msg
 * @param {Buffer} signature
 * @param {number} recovery
 * @return {Buffer}
 */
exports.recoverSync = secp256k1.recoverSync

/**
 * Compute an EC Diffie-Hellman secret.
 * @method ecdh
 * @param {Buffer} publicKey
 * @param {Buffer} secretKey
 * @param {function} [callback]
 * @return {Promise<Buffer>}
 */
exports.ecdh = function (publicKey, secretKey, callback) {
  if (callback !== undefined && typeof callback !== 'function') {
    throw new TypeError('callback must be a function')
  }

  return new exports.Promise(function (resolve, reject) {
    secp256k1.ecdh(publicKey, secretKey, function (err, result) {
      if (callback !== undefined) {
        setImmediate(callback, err, result)
      }

      if (err === null) {
        resolve(result)
      } else {
        reject(err)
      }
    })
  })
}

/**
 * Synchronous .ecdh
 * @method recoverSync
 * @param {Buffer} publicKey
 * @param {Buffer} secretKey
 * @return {Buffer}
 */
exports.ecdhSync = secp256k1.ecdhSync
