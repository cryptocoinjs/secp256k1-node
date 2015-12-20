'use strict'

var assert = require('./lib/assert')
var messages = require('./lib/messages.json')

/**
 * @param {Buffer} signature
 * @return {Buffer}
 */
exports.signatureNormalize = function (signature) {
  assert.isBuffer(signature, messages.ECDSA_SIGNATURE_TYPE_INVALID)
  assert.isBufferLength(signature, 64, messages.ECDSA_SIGNATURE_LENGTH_INVALID)
}

/**
 * @param {Buffer} signature
 * @return {Buffer}
 */
exports.signatureExport = function (signature) {
  assert.isBuffer(signature, messages.ECDSA_SIGNATURE_TYPE_INVALID)
  assert.isBufferLength(signature, 64, messages.ECDSA_SIGNATURE_LENGTH_INVALID)
}

/**
 * @param {Buffer} signature
 * @return {Buffer}
 */
exports.signatureImport = function (signature) {
  assert.isBuffer(signature, messages.ECDSA_SIGNATURE_TYPE_INVALID)
  assert.isLengthGTZero(signature, messages.ECDSA_SIGNATURE_LENGTH_INVALID)
}
