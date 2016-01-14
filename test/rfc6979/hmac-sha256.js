'use strict'

var expect = require('chai').expect
var crypto = require('crypto')

var hmacSHA256 = require('../../lib/js/rfc6979/hmac-sha256')
var util = require('../util')

/**
 * @param {Buffer} key
 * @param {Buffer} data
 * @return {Buffer}
 */
function cryptoHmacSHA256 (key, data) {
  return crypto.createHmac('sha256', key).update(data).digest()
}

describe('hmac-sha256', function () {
  this.timeout(util.env.repeat * 10)

  before(function () {
    util.setSeed(util.env.seed)
  })

  util.repeatIt('random tests', util.env.repeat, function () {
    var key = util.getMessage()
    var data = Buffer.concat([util.getMessage(), util.getMessage()]).slice(util.getMessage()[0] % 16)
    var dgst = hmacSHA256(key, data)
    expect(dgst.toString('hex')).to.equal(cryptoHmacSHA256(key, data).toString('hex'))
  })
})
