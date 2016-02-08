'use strict'
/* global describe, it */

var expect = require('chai').expect

var rfc6979 = require('../../lib/js/rfc6979')

describe('rfc6979', function () {
  it('optional nonce argument do not have equivalent effect', function () {
    var zeros = new Buffer(32)
    zeros.fill(0)

    var nonce1 = rfc6979(zeros, zeros, null, null, 0).toString('hex')
    var nonce2 = rfc6979(zeros, zeros, null, zeros, 0).toString('hex')
    var nonce3 = rfc6979(zeros, zeros, zeros.slice(0, 16), null, 0).toString('hex')
    var nonce4 = rfc6979(zeros, zeros, zeros.slice(0, 16), zeros, 0).toString('hex')

    expect(nonce1).to.not.equal(nonce2)
    expect(nonce1).to.not.equal(nonce3)
    expect(nonce1).to.not.equal(nonce4)
    expect(nonce2).to.not.equal(nonce3)
    expect(nonce2).to.not.equal(nonce4)
    expect(nonce3).to.not.equal(nonce4)
  })
})
