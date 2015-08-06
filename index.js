var crypto = require('crypto')

function pad32(msg) {
  var buf
  if (msg.length < 32) {
    buf = new Buffer(32)
    buf.fill(0)
    msg.copy(buf, 32 - msg.length)
    return buf
  } else
    return msg
}

/**
 * This module provides native bindings to ecdsa [secp256k1](https://github.com/bitcoin/secp256k1) functions
 * @module secp256k1
 */

var secpNode = require('bindings')('secp256k1')

/**
 * Verify an ECDSA secret key.
 * @method verifySecetKey
 * @param {Buffer} sercetKey the sercet Key to verify
 * @return {Boolean}  `true` if sercet key is valid, `false` sercet key is invalid
 */
exports.verifySecretKey = function (sercetKey) {
  return Boolean(secpNode.secKeyVerify(sercetKey))
}

/**
 * Verify an ECDSA public key.
 * @method verifyPublicKey
 * @param {Buffer} publicKey the public Key to verify
 * @return {Boolean} `true` if public key is valid, `false` sercet key is invalid
 */
exports.verifyPublicKey = function (publicKey) {
  return Boolean(secpNode.pubKeyVerify(publicKey))
}

/**
 * Create an ECDSA signature.
 * @method sign
 * @param  {Buffer} secretkey a 32-byte secret key (assumed to be valid)
 * @param {Buffer} msg he message being signed
 * @param {Function} cb the callback given. The callback is given the signature
 * @returns {Buffer} if no callback is given a 72-byte signature is returned
 */
exports.sign = function (msg, secretKey, DER, cb) {
  if (typeof DER === 'function') {
    cb = DER
    DER = false
  }

  if (!DER) {
    DER = false
  }

  var result
  if (typeof cb === 'function')
    secpNode.sign(pad32(msg), secretKey, DER, cb)
  else {
    var result = secpNode.sign(pad32(msg), secretKey, DER)
    if (DER)
      return result[0]
    else {
      return {
        signature: result[0],
        recovery: result[1]
      }
    }
  }
}

/**
 * Verify an ECDSA signature.
 * @method verify
 * @param {Buffer} mgs the message
 * @param {Buffer|Object} sig the signature
 * @param {Buffer} pubKey the public key
 * @return {Integer}
 *
 *    - 1: correct signature
 *    - 0: incorrect signature
 */
exports.verify = function (msg, sig, pubKey, cb) {

  var recid = recid ? sig.recovery : -1

  if(sig.signature)
    sig = sig.signature

  var DER = true
  if (sig.length === 64)
    DER = false

  if (cb) {
    secpNode.verify(pubKey, pad32(msg), sig, recid, DER, cb)
  } else
    return secpNode.verify(pubKey, pad32(msg), sig, recid, DER)
}

/**
 * Recover an ECDSA public key from a compact signature. In the process also verifing it.
 * @method recoverCompact
 * @param {Buffer} msg the message assumed to be signed
 * @param {Buffer} sig the signature as 64 byte buffer
 * @param {Integer} recid the recovery id (as returned by ecdsa_sign_compact)
 * @param {Boolean} compressed whether to recover a compressed or uncompressed pubkey
 * @param {Function} [cb]
 * @return {Buffer} the pubkey, a 33 or 65 byte buffer
 */
exports.recover = function (msg, sig, compressed, cb) {

  var recid = sig.recovery !== undefined ? sig.recovery : -1

  if(sig.signature)
    sig = sig.signature

  var DER = true
  if (sig.length === 64)
    DER = false


  if (typeof compressed === 'function'){
    cb = compressed
    compressed = true
  }

  if(compressed === undefined){
    compressed = true
  }

  if (!DER &&( recid < 0 || recid > 3)) {
    var error = new Error('recovery id must be >= 0 && recid <= 3')
    if (typeof cb !== 'function')
      throw error
    else
      return cb(error)
  }

  if (!cb)
    return secpNode.recover(pad32(msg), sig, recid, compressed, DER)
  else
    secpNode.recover(pad32(msg), sig, recid, compressed, DER, cb)
}

/**
 * Compute the public key for a secret key.
 * @method createPubKey
 * @param {Buffer} secKey a 32-byte private key.
 * @param {Boolean} [compressed=0] whether the computed public key should be compressed
 * @return {Buffer} a 33-byte (if compressed) or 65-byte (if uncompressed) area to store the public key.
 */
exports.createPublicKey = function (secKey, compressed) {
  if (!secKey)
    throw new Error('invalid private key')

  compressed = compressed ? 1 : 0
  return secpNode.pubKeyCreate(secKey, compressed)
}

/**
 * @method exportPrivateKey
 * @param {Buffer} secertKey
 * @param {Boolean} compressed
 * @return {Buffer} privateKey
 */
exports.exportPrivateKey = secpNode.privKeyExport

/**
 * @method importPrivateKey
 * @param {Buffer} privateKey
 * @return {Buffer} secertKey
 */
exports.importPrivateKey = secpNode.privKeyImport

/**
 * @method decompressPublickey
 * @param {Buffer} secretKey
 * @return {Buffer}
 */
exports.decompressPublicKey = secpNode.pubKeyDecompress

/**
 * @method privKeyTweakAdd
 * @param {Buffer} privateKey
 * @param {Buffer} tweak
 * @return {Buffer}
 */
exports.privKeyTweakAdd = secpNode.privKeyTweakAdd

/**
 * @method privKeyTweakMul
 * @param {Buffer} privateKey
 * @param {Buffer} tweak
 * @return {Buffer}
 */
exports.privKeyTweakMul = secpNode.privKeyTweakMul

/**
 * @method pubKeyTweakAdd
 * @param {Buffer} publicKey
 * @param {Buffer} tweak
 * @return {Buffer}
 */
exports.pubKeyTweakAdd = secpNode.pubKeyTweakAdd

/**
 * @method pubKeyTweakMul
 * @param {Buffer} publicKey
 * @param {Buffer} tweak
 * @return {Buffer}
 */
exports.pubKeyTweakMul = secpNode.pubKeyTweakMul
