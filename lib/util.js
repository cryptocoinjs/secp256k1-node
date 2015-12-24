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
  var ws2 = ws << 1
  var k = num.clone()
  while (k.cmpn(0) === 1) {
    var z
    if (k.isOdd()) {
      var mod = k.andln(ws2 - 1)
      z = (mod >= ws) ? (ws - mod) : mod
      k.isubn(z)
    } else {
      z = 0
    }
    naf.push(z)

    // Optimization, shift by word if possible
    var shift = (k.cmpn(0) !== 0 && k.andln(ws2 - 1) === 0) ? (w + 1) : 1
    for (var i = 1; i < shift; i++) {
      naf.push(0)
    }

    k.iushrn(shift)
  }

  return naf
}

/**
 * Represent k1, k2 in a Joint Sparse Form
 * @param {BN} k1
 * @param {BN} k2
 * @return {[number[], number[]]}
 */
exports.getJSF = function (k1, k2) {
  var jsf = [[], []]

  k1 = k1.clone()
  k2 = k2.clone()
  var d1 = 0
  var d2 = 0
  while (k1.cmpn(-d1) > 0 || k2.cmpn(-d2) > 0) {
    // First phase
    var m14 = (k1.andln(3) + d1) & 3
    var m24 = (k2.andln(3) + d2) & 3
    if (m14 === 3) {
      m14 = -1
    }
    if (m24 === 3) {
      m24 = -1
    }

    var m8
    var u1
    if ((m14 & 1) === 0) {
      u1 = 0
    } else {
      m8 = (k1.andln(7) + d1) & 7
      u1 = ((m8 === 3 || m8 === 5) && m24 === 2) ? (-m14) : m14
    }
    jsf[0].push(u1)

    var u2
    if ((m24 & 1) === 0) {
      u2 = 0
    } else {
      m8 = (k2.andln(7) + d2) & 7
      u2 = ((m8 === 3 || m8 === 5) && m14 === 2) ? (-m24) : m24
    }
    jsf[1].push(u2)

    // Second phase
    if (2 * d1 === u1 + 1) {
      d1 = 1 - d1
    }
    if (2 * d2 === u2 + 1) {
      d2 = 1 - d2
    }
    k1.iushrn(1)
    k2.iushrn(1)
  }

  return jsf
}
