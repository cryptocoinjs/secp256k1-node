'use strict'

var expect = require('chai').expect
var crypto = require('crypto')

var sha256 = require('../../lib/js/rfc6979/sha256')
var util = require('../util')

/**
 * @param {Buffer} data
 * @return {Buffer}
 */
function cryptoSHA256 (data) {
  return crypto.createHash('sha256').update(data).digest()
}

describe('sha256', function () {
  this.timeout(util.env.repeat * 10)

  before(function () {
    util.setSeed(util.env.seed)
  })

  util.repeatIt('random tests', util.env.repeat, function () {
    var data = Buffer.concat([util.getMessage(), util.getMessage()]).slice(util.getMessage()[0] % 16)
    var dgst = sha256(data)
    expect(dgst.toString('hex')).to.equal(cryptoSHA256(data).toString('hex'))
  })
})
