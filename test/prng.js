'use strict'

var randomBytes = require('crypto').randomBytes
var createHash = require('create-hash/browser')

var MAX_COUNT = Math.pow(2, 32)

/**
 * Hash-based PRNG with 2**32 loop
 * @class PRNG
 * @param {(Buffer|string)} [seed]
 */
function PRNG (seed) {
  this.setSeed(seed)
}

/**
 * @param {Buffer} data
 * @return {Buffer}
 */
PRNG.prototype._sha256 = function (data) {
  return createHash('sha256').update(data).digest()
}

/**
 * @param {(Buffer|string)} [seed]
 */
PRNG.prototype.setSeed = function (seed) {
  if (seed === undefined) {
    seed = randomBytes(32)
  }

  if (typeof seed === 'string' && seed.length % 2 === 0 && seed.match(/^[0-1]*$/) !== null) {
    seed = new Buffer(seed, 'hex')
  }

  this._count = 0
  this._seed = Buffer.concat([new Buffer(4), this._sha256(seed)])
}

/**
 * @return {Buffer}
 */
PRNG.prototype.random = function () {
  if (this._count === MAX_COUNT) {
    this._count = 0
  }

  this._seed.writeUInt32BE(this._count++, 0)
  return this._sha256(this._seed)
}

module.exports = PRNG
