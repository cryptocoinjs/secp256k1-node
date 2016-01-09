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

/**
 * Represent num in a w-NAF form
 * @param {BN} num
 * @param {number} w
 * @return {number[]}
 */
exports.getNAF = function (num, w) {
  var naf = []
  var ws = 1 << w
  var ws2m1 = (ws << 1) - 1
  for (var k = num.clone(); k.cmpn(0) === 1; k.iushrn(1)) {
    var z = 0
    if (k.isOdd()) {
      var mod = k.andln(ws2m1)
      z = (mod >= ws) ? (ws - mod) : mod
      k.isubn(z)
    }
    naf.push(z)
  }

  return naf
}
