'use strict'

var expect = require('chai').expect
var crypto = require('crypto')

var hmacSHA256 = require('../../lib/js/rfc6979/hmac-sha256')
var util = require('../util')

var fixtures = [
  {
    'name': 'nist 1 (with hashed key, changed res)',
    'key': 'fdeab9acf3710362bd2658cdc9a29e8f9c757fcf9811603a8c447cd1d9151108',
    'msg': 'Sample message for keylen=blocklen',
    'res': '571c1613f6ee30dd0b694b63e0945ef9d034ba0c676b549133ca44f4efcd44d9'
  },
  {
    'name': 'nist 2',
    'key': '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    'msg': 'Sample message for keylen<blocklen',
    'res': 'a28cf43130ee696a98f14a37678b56bcfcbdd9e5cf69717fecf5480f0ebdf790'
  },
  {
    'name': 'nist 3 (with hashed key)',
    'key': 'bce0aff19cf5aa6a7469a30d61d04e4376e4bbf6381052ee9e7f33925c954d52',
    'msg': 'Sample message for keylen=blocklen',
    'res': 'bdccb6c72ddeadb500ae768386cb38cc41c63dbb0878ddb9c7a38a431b78378d'
  },
  {
    'name': 'nist 4 (with hashed key, changed res)',
    'key': '7509fe148e2c426ed16c990f22fe8116905c82c561756e723f63223ace0e147e',
    'msg': 'Sample message for keylen<blocklen, with truncated tag',
    'res': 'cdd26dd2580e9793694f1fde064e6c914b37dc726cc4e38d251a057fafbf63c8'
  }
]

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

  fixtures.forEach(function (fixture) {
    it(fixture.name, function () {
      var key = new Buffer(fixture.key, 'hex')
      var msg = new Buffer(fixture.msg, 'utf8')
      expect(hmacSHA256(key, msg).toString('hex')).to.equal(fixture.res)
    })
  })

  util.repeatIt('random tests', util.env.repeat, function () {
    var key = util.getMessage()
    var data = Buffer.concat([util.getMessage(), util.getMessage()]).slice(util.getMessage()[0] % 16)
    var dgst = hmacSHA256(key, data)
    expect(dgst.toString('hex')).to.equal(cryptoHmacSHA256(key, data).toString('hex'))
  })
})
