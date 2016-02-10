'use strict'
/* global before, describe */

var expect = require('chai').expect
var createHash = require('create-hash/browser')

var sha256 = require('../../lib/js/rfc6979/sha256')
var util = require('../util')

/**
 * @param {Buffer} data
 * @return {Buffer}
 */
function cryptoSHA256 (data) {
  return createHash('sha256').update(data).digest()
}

describe('sha256', function () {
  this.timeout(util.env.repeat * 10)

  before(function () {
    util.setSeed(util.env.seed)
  })

  /**
   * @param {string} data
   * @param {string} digest
   */
  function test (data, digest) {
    var dgst = sha256(new Buffer(data))
    expect(dgst.toString('hex')).to.equal(digest)
  }

  test('abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  test('', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
  test('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq', '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1')
  test(new Array(1000001).join('a'), 'cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0')

  util.repeatIt('random tests', util.env.repeat, function () {
    var data = Buffer.concat([util.getMessage(), util.getMessage()]).slice(util.getMessage()[0] % 16)
    var dgst = sha256(data)
    expect(dgst.toString('hex')).to.equal(cryptoSHA256(data).toString('hex'))
  })
})
