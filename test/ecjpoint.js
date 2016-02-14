'use strict'
/* global describe, before, it */

var expect = require('chai').expect
var ECPoint = require('../lib/js/ecpoint')
var ECJPoint = require('../lib/js/ecjpoint')
var BN = require('../lib/js/bn')

var util = require('./util')

describe('ECJPoint', function () {
  this.timeout(util.env.repeat * 100 * (util.env.isTravis ? 5 : 1))

  before(function () {
    util.setSeed(util.env.seed)
  })

  describe('neg', function () {
    it('return infinity for infinity', function () {
      var ecjpoint = new ECJPoint(null, null, null)
      expect(ecjpoint.neg().inf).to.be.true
    })

    util.repeatIt('random tests', util.env.repeat, function () {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecjpoint = ECPoint.fromPublicKey(publicKey).toECJPoint()
      var result = ecjpoint.neg()
      expect(result.x.ucmp(ecjpoint.x)).to.equal(0)
      expect(result.y.ucmp(ecjpoint.y.redNeg())).to.equal(0)
      expect(result.z.ucmp(ecjpoint.z)).to.equal(0)
    })
  })

  describe('add', function () {
    it('O + P -> P', function () {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecjpoint1 = new ECJPoint(null, null, null)
      var ecjpoint2 = ECPoint.fromPublicKey(publicKey).toECJPoint()
      var result = ecjpoint1.add(ecjpoint2)
      expect(result.x.ucmp(ecjpoint2.x)).to.equal(0)
      expect(result.y.ucmp(ecjpoint2.y)).to.equal(0)
      expect(result.z.ucmp(ecjpoint2.z)).to.equal(0)
    })

    it('P + O -> P', function () {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecjpoint1 = ECPoint.fromPublicKey(publicKey).toECJPoint()
      var ecjpoint2 = new ECJPoint(null, null, null)
      var result = ecjpoint1.add(ecjpoint2)
      expect(result.x.ucmp(ecjpoint1.x)).to.equal(0)
      expect(result.y.ucmp(ecjpoint1.y)).to.equal(0)
      expect(result.z.ucmp(ecjpoint1.z)).to.equal(0)
    })

    it('P + P -> 2P', function () {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecjpoint = ECPoint.fromPublicKey(publicKey).toECJPoint()
      var expected = ecjpoint.dbl()
      var result = ecjpoint.add(ecjpoint)
      expect(result.x.ucmp(expected.x)).to.equal(0)
      expect(result.y.ucmp(expected.y)).to.equal(0)
      expect(result.z.ucmp(expected.z)).to.equal(0)
    })

    it('P + (-P) -> O', function () {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecjpoint = ECPoint.fromPublicKey(publicKey).toECJPoint()
      var result = ecjpoint.add(ecjpoint.neg())
      expect(result.inf).to.be.true
    })
  })

  describe('mixedAdd', function () {
    it('O + P -> P', function () {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecjpoint = new ECJPoint(null, null, null)
      var ecpoint = ECPoint.fromPublicKey(publicKey)
      var result = ECPoint.fromECJPoint(ecjpoint.mixedAdd(ecpoint))
      expect(result.x.ucmp(ecpoint.x)).to.equal(0)
      expect(result.y.ucmp(ecpoint.y)).to.equal(0)
    })

    it('P + O -> P', function () {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecjpoint = ECPoint.fromPublicKey(publicKey).toECJPoint()
      var ecpoint = new ECPoint(null, null)
      var result = ecjpoint.mixedAdd(ecpoint)
      expect(result.x.ucmp(ecjpoint.x)).to.equal(0)
      expect(result.y.ucmp(ecjpoint.y)).to.equal(0)
      expect(result.z.ucmp(ecjpoint.z)).to.equal(0)
    })

    it('P + P -> 2P', function () {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecpoint = ECPoint.fromPublicKey(publicKey)
      var expected = ecpoint.toECJPoint().dbl()
      var result = ecpoint.toECJPoint().mixedAdd(ecpoint)
      expect(result.x.ucmp(expected.x)).to.equal(0)
      expect(result.y.ucmp(expected.y)).to.equal(0)
      expect(result.z.ucmp(expected.z)).to.equal(0)
    })

    it('P + (-P) -> O', function () {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecpoint = ECPoint.fromPublicKey(publicKey)
      var result = ecpoint.toECJPoint().mixedAdd(ecpoint.neg())
      expect(result.inf).to.be.true
    })

    util.repeatIt('random tests (add/mixedAdd)', util.env.repeat, function () {
      var publicKey1 = util.getPublicKey(util.getPrivateKey()).compressed
      var ecjpoint = ECPoint.fromPublicKey(publicKey1).toECJPoint()
      var publicKey2 = util.getPublicKey(util.getPrivateKey()).compressed
      var ecpoint = ECPoint.fromPublicKey(publicKey2)
      var expected = ecjpoint.add(ecpoint.toECJPoint())
      var result = ecjpoint.mixedAdd(ecpoint)
      expect(result.x.ucmp(expected.x)).to.equal(0)
      expect(result.y.ucmp(expected.y)).to.equal(0)
      expect(result.z.ucmp(expected.z)).to.equal(0)
    })
  })

  describe('dbl', function () {
    it('doubling infinity', function () {
      var ecjpoint = new ECJPoint(null, null, null)
      expect(ecjpoint.dbl().inf).to.be.true
    })

    it('2P = 0 (y is same)', function () {
      var bn = BN.fromBuffer(util.getMessage())
      var ecjpoint = new ECPoint(bn, BN.fromNumber(0)).toECJPoint()
      expect(ecjpoint.dbl().inf).to.be.true
    })

    util.repeatIt('random tests', util.env.repeat, function () {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecjpoint = ECPoint.fromPublicKey(publicKey).toECJPoint()
      var expected = ecjpoint.add(ecjpoint)
      var result = ecjpoint.dbl()
      expect(result.x.ucmp(expected.x)).to.equal(0)
      expect(result.y.ucmp(expected.y)).to.equal(0)
      expect(result.z.ucmp(expected.z)).to.equal(0)
    })
  })

  describe('dblp', function () {
    util.repeatIt('random tests (pow from 0 to 10)', util.env.repeat, function () {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecjpoint = ECPoint.fromPublicKey(publicKey).toECJPoint()
      for (var i = 0, expected = ecjpoint; i < 10; ++i, expected = expected.dbl()) {
        var result = ecjpoint.dblp(i)
        expect(result.x.ucmp(expected.x)).to.equal(0)
        expect(result.y.ucmp(expected.y)).to.equal(0)
        expect(result.z.ucmp(expected.z)).to.equal(0)
      }
    })
  })
})
