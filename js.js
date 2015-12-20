/**
 * @param {Buffer} privateKey
 * @return {boolean}
 */
exports.privateKeyVerify = function (privateKey) {}

/**
 * @param {Buffer} privateKey
 * @param {boolean} [compressed=true]
 * @return {Buffer}
 */
exports.privateKeyExport = function (privateKey, compressed) {}

/**
 * @param {Buffer} privateKey
 * @return {Buffer}
 */
exports.privateKeyImport = function (privateKey) {}

/**
 * @param {Buffer} privateKey
 * @param {Buffer} tweak
 * @return {Buffer}
 */
exports.privateKeyTweakAdd = function (privateKey, tweak) {}

/**
 * @param {Buffer} privateKey
 * @param {Buffer} tweak
 * @return {Buffer}
 */
exports.privateKeyTweakMul = function (privateKey, tweak) {}

/**
 * @param {Buffer} privateKey
 * @param {boolean} [compressed=true]
 * @return {Buffer}
 */
exports.publicKeyCreate = function (privateKey, compressed) {}

/**
 * @param {Buffer} publicKey
 * @param {boolean} [compressed=true]
 * @return {Buffer}
 */
exports.publicKeyConvert = function (publicKey, compressed) {}

/**
 * @param {Buffer} publicKey
 * @return {boolean}
 */
exports.publicKeyVerify = function (publicKey) {}

/**
 * @param {Buffer} publicKey
 * @param {Buffer} tweak
 * @param {boolean} [compressed=true]
 * @return {Buffer}
 */
exports.publicKeyTweakAdd = function (publicKey, tweak, compressed) {}

/**
 * @param {Buffer} publicKey
 * @param {Buffer} tweak
 * @param {boolean} [compressed=true]
 * @return {Buffer}
 */
exports.publicKeyTweakMul = function (publicKey, tweak, compressed) {}

/**
 * @param {Buffer[]} publicKeys
 * @param {boolean} [compressed=true]
 * @return {Buffer}
 */
exports.publicKeyCombine = function (publicKeys, compressed) {}

/**
 * @param {Buffer} signature
 * @return {Buffer}
 */
exports.signatureNormalize = function (signature) {}

/**
 * @param {Buffer} signature
 * @return {Buffer}
 */
exports.signatureExport = function (signature) {}

/**
 * @param {Buffer} signature
 * @return {Buffer}
 */
exports.signatureImport = function (signature) {}

/**
 * @callback sign~noncefn
 * @param {Buffer} message
 * @param {Buffer} privateKey
 * @param {?Buffer} algo
 * @param {?Buffer} data
 * @param {number} attempt
 * @return {Buffer}
 */

/**
 * @typedef {Object} sign~options
 * @param {Buffer} [data]
 * @param {sign~noncefn} [noncefn=secp256k1_nonce_function_rfc6979]
 */

/**
 * @param {Buffer} message
 * @param {Buffer} privateKey
 * @param {sign~options} [options]
 * @return {{signature: Buffer, recovery: number}}
 */
exports.sign = function (message, privateKey, options) {}

/**
 * @param {Buffer} message
 * @param {Buffer} signature
 * @param {Buffer} publicKey
 * @return {boolean}
 */
exports.verify = function (message, signature, publicKey) {}

/**
 * @param {Buffer} message
 * @param {Buffer} signature
 * @param {number} recovery
 * @param {boolean} [compressed=true]
 * @return {Buffer}
 */
exports.recover = function (message, signature, recovery, compressed) {}

/**
 * @param {Buffer} publicKey
 * @param {Buffer} privateKey
 * @param {?} options
 * @return {Buffer}
 */
// exports.ecdh = function (publicKey, privateKey, options) {}
