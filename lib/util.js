'use strict'

var assert = require('./assert')
var messages = require('./messages.json')

/**
 * @param {*} value
 * @param {boolean} defaultValue
 * @return {boolean}
 */
exports.initCompressedValue = function (value, defaultValue) {
  if (value === undefined) {
    return defaultValue
  }

  assert.isBoolean(value, messages.COMPRESSED_TYPE_INVALID)
  return value
}
