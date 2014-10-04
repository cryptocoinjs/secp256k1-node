/**
 * This module provides native bindings to ecdsa [secp256k1](https://github.com/bitcoin/secp256k1) functions
 * @module secp256k1
 */

var secpNode = require('bindings')('secp256k1');
var assert = require('assert');

/**
 * Verify an ECDSA secret key.
 * @method verifySecetKey
 * @param {Buffer} sercetKey the sercet Key to verify
 * @return {Boolean}  `true` if sercet key is valid, `false` sercet key is invalid
 */
exports.verifySecretKey = function(sercetKey){
  return Boolean(secpNode.secKeyVerify(sercetKey));
};

/**
 * Verify an ECDSA public key.
 * @method verifyPublicKey
 * @param {Buffer} publicKey the public Key to verify
 * @return {Boolean} `true` if public key is valid, `false` sercet key is invalid
 */
exports.verifyPublicKey = function(publicKey){
  return Boolean(secpNode.pubKeyVerify(publicKey));
};

/** 
 * Create an ECDSA signature.
 * @method sign
 * @param  {Buffer} secretkey a 32-byte secret key (assumed to be valid)
 * @param {Buffer} msg he message being signed
 * @param {Function} cb the callback given. The callback is given the signature 
 * @returns {Buffer} if no callback is given a 72-byte signature is returned
 */
exports.sign = function(secretKey, msg, cb){
  if(cb){
    secpNode.signAsync(secretKey, msg, cb);
  }else{
    return secpNode.sign(secretKey, msg);
  }
};

/**
 * Create a compact ECDSA signature (64 byte + recovery id). Runs asyncously
 * if given a callback
 * @method signCompact 
 * @param {Buffer} sercetKey a 32-byte secret key (assumed to be valid)
 * @param {Buffer} msg the message being signed
 * @param {Function} [cb] the callback which is give `err`, `sig` the  
 *    @param {Buffer} sig  a 64-byte buffer repersenting the signature
 *    @param {Number} recid: an int which is the recovery id.
 * @return {Object} result only if no callback is given will the result be returned
 *    result.sigature
 *    result.r
 *    result.s
 *    result.recoveryID
 */
exports.signCompact = function(secretKey, msg, cb){

  assert(secretKey.length === 32, 'the secret key needs tobe 32 bytes');

  if(cb){
    secpNode.signCompactAsync(secretKey, msg, cb);
  }else{
    var array = secpNode.signCompact(secretKey, msg);
    return {
      recoveryId: array[1],
      signature: array[2],
      r: array[2].slice(0, 32),
      s: array[2].slice(32, 64)
    };
  }
};


/**
 * Verify an ECDSA signature.
 * @method verify
 * @param {Buffer} pubKey the public key
 * @param {Buffer} mgs the message
 * @param {Buffer} sig the signature
 * @return {Integer} 
 *    1: correct signature
 *    0: incorrect signature
 *   -1: invalid public key
 *   -2: invalid signature
 */
exports.verify = function(pubKey, msg, sig, cb){
  if(cb){
    secpNode.verifyAsync(pubKey, msg, sig, cb);
  }else{
    return secpNode.verify(pubKey, msg, sig);
  }
};

/**
 * Recover an ECDSA public key from a compact signature. In the process also verifing it.
 * @method recoverCompact
 * @param {Buffer} msg the message assumed to be signed
 * @param {Buffer} sig the signature as 64 byte buffer
 * @param {Boolean} compressed whether to recover a compressed or uncompressed pubkey
 * @param {Integer} recid the recovery id (as returned by ecdsa_sign_compact)
 * @param {Function} [cb]
 * @return {Buffer} the pubkey, a 33 or 65 byte buffer
 */
exports.recoverCompact = function(msg, sig, compressed, recid, cb){
  if(!cb){
    return secpNode.recoverCompact(msg, sig, compressed, recid); 
  }else{
    secpNode.recoverCompactAsync(msg, sig, compressed, recid,  cb);
  }
};

/** 
 * Compute the public key for a secret key.
 * @method createPubKey
 * @param {Buffer} secKey a 32-byte private key.
 * @param {Boolean} [compressed=0] whether the computed public key should be compressed
 * @return {Buffer} a 33-byte (if compressed) or 65-byte (if uncompressed) area to store the public key.
 */
exports.createPublicKey = function(secKey, compressed){
  assert(secKey.length === 32, 'the sercet key needs to be 32 bytes');
  compressed = compressed ? 1 : 0;
  return secpNode.pubKeyCreate(secKey, compressed);
};

/**
 * @method exportPrivateKey
 * @param {Buffer} secertKey
 * @param {Boolean} compressed
 * @return {Buffer} privateKey
 */
exports.exportPrivateKey = secpNode.privKeyExport;

/**
 * @method importPrivateKey
 * @param {Buffer} privateKey
 * @return {Buffer} secertKey 
 */
exports.importPrivateKey = secpNode.privKeyImport;

/**
 * @method decompressPublickey
 * @param {Buffer} secretKey
 * @return {Buffer}
 */ 
exports.decompressPublicKey = secpNode.pubKeyDecompress;
