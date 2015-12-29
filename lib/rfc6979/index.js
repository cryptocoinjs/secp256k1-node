'use strict'

var hmacSHA256 = require('./hmac-sha256')

/**
 * @param {Buffer} message
 * @param {Buffer} privateKey
 * @param {?Buffer} algo
 * @param {?Buffer} data
 * @param {number} attempt
 * @return {Buffer}
 */
module.exports = function (message, privateKey, algo, data, counter) {
  var key = Buffer.concat([
    privateKey,
    message,
    algo !== null ? algo : new Buffer(0),
    data !== null ? data : new Buffer(0)
  ])

  // 3.2.b
  var v = new Buffer(32)
  v.fill(0x01)

  // 3.2.c
  var k = new Buffer(32)
  k.fill(0x00)

  // 3.2.d
  k = hmacSHA256(k, Buffer.concat([v, new Buffer([0]), key]))

  // 3.2.e
  v = hmacSHA256(k, v)

  // 3.2.f
  k = hmacSHA256(k, Buffer.concat([v, new Buffer([1]), key]))

  // 3.2.g
  v = hmacSHA256(k, v)

  // 3.2.h
  v = hmacSHA256(k, v)
  for (var i = 0; i < counter; ++i) {
    k = hmacSHA256(k, Buffer.concat([v, new Buffer([0])]))
    v = hmacSHA256(k, v)
  }

  return v
}
