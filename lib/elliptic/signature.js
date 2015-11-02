var asserts = require('../asserts')
var messages = require('../messages')

/**
 * Convert a signature to a normalized lower-S form.
 * @method signatureNormalize
 * @param {Buffer} signature
 * @return {Buffer}
 */
exports.signatureNormalize = function (signature) {
  asserts.checkTypeBuffer(signature, messages.ECDSA_SIGNATURE_TYPE_INVALID)
  asserts.checkBufferLength(signature, 64, messages.ECDSA_SIGNATURE_LENGTH_INVALID)

  // TODO
}

/**
 * Serialize an ECDSA signature in DER format.
 * @method signatureExport
 * @param {Buffer} signature
 * @return {Buffer}
 */
exports.signatureExport = function (signature) {
  asserts.checkTypeBuffer(signature, messages.ECDSA_SIGNATURE_TYPE_INVALID)
  asserts.checkBufferLength(signature, 64, messages.ECDSA_SIGNATURE_LENGTH_INVALID)

  // TODO
}

/**
 * Parse a DER ECDSA signature.
 * @method signatureImport
 * @param {Buffer} signature
 * @return {Buffer}
 */
exports.signatureImport = function (signature) {
  asserts.checkTypeBuffer(signature, messages.ECDSA_SIGNATURE_TYPE_INVALID)

  // TODO
}
