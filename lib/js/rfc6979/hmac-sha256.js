'use strict'

var sha256 = require('./sha256')

/**
 * @param {Buffer} key
 * @param {Buffer} data
 * @return {Buffer}
 */
module.exports = function (key, data) {
  // block size in bytes (64 for sha256)
  var hkey = new Buffer(64)
  key.copy(hkey, 0)
  hkey.fill(0, 32, 64)

  for (var i = 0; i < 64; ++i) {
    hkey[i] = hkey[i] ^ 0x36
  }
  data = sha256(Buffer.concat([hkey, data]))

  for (var j = 0; j < 64; ++j) {
    hkey[j] = hkey[j] ^ 0x6a
  }
  return sha256(Buffer.concat([hkey, data]))
}
