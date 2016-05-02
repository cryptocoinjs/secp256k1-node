'use strict'
var test = require('tape')
var ECPoint = require('../lib/js/ecpoint')
var ECJPoint = require('../lib/js/ecjpoint')
var BN = require('../lib/js/bn')

var util = require('./util')

test('ECJPoint', function (t) {
  util.setSeed(util.env.seed)

  t.test('neg', function (t) {
    t.test('return infinity for infinity', function (t) {
      var ecjpoint = new ECJPoint(null, null, null)
      t.true(ecjpoint.neg().inf)
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecjpoint = ECPoint.fromPublicKey(publicKey).toECJPoint()
      var result = ecjpoint.neg()
      t.same(result.x.ucmp(ecjpoint.x), 0)
      t.same(result.y.ucmp(ecjpoint.y.redNeg()), 0)
      t.same(result.z.ucmp(ecjpoint.z), 0)
      t.end()
    })

    t.end()
  })

  t.test('add', function (t) {
    t.test('O + P -> P', function (t) {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecjpoint1 = new ECJPoint(null, null, null)
      var ecjpoint2 = ECPoint.fromPublicKey(publicKey).toECJPoint()
      var result = ecjpoint1.add(ecjpoint2)
      t.same(result.x.ucmp(ecjpoint2.x), 0)
      t.same(result.y.ucmp(ecjpoint2.y), 0)
      t.same(result.z.ucmp(ecjpoint2.z), 0)
      t.end()
    })

    t.test('P + O -> P', function (t) {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecjpoint1 = ECPoint.fromPublicKey(publicKey).toECJPoint()
      var ecjpoint2 = new ECJPoint(null, null, null)
      var result = ecjpoint1.add(ecjpoint2)
      t.same(result.x.ucmp(ecjpoint1.x), 0)
      t.same(result.y.ucmp(ecjpoint1.y), 0)
      t.same(result.z.ucmp(ecjpoint1.z), 0)
      t.end()
    })

    t.test('P + P -> 2P', function (t) {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecjpoint = ECPoint.fromPublicKey(publicKey).toECJPoint()
      var expected = ecjpoint.dbl()
      var result = ecjpoint.add(ecjpoint)
      t.same(result.x.ucmp(expected.x), 0)
      t.same(result.y.ucmp(expected.y), 0)
      t.same(result.z.ucmp(expected.z), 0)
      t.end()
    })

    t.test('P + (-P) -> O', function (t) {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecjpoint = ECPoint.fromPublicKey(publicKey).toECJPoint()
      var result = ecjpoint.add(ecjpoint.neg())
      t.true(result.inf)
      t.end()
    })

    t.end()
  })

  t.test('mixedAdd', function (t) {
    t.test('O + P -> P', function (t) {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecjpoint = new ECJPoint(null, null, null)
      var ecpoint = ECPoint.fromPublicKey(publicKey)
      var result = ECPoint.fromECJPoint(ecjpoint.mixedAdd(ecpoint))
      t.same(result.x.ucmp(ecpoint.x), 0)
      t.same(result.y.ucmp(ecpoint.y), 0)
      t.end()
    })

    t.test('P + O -> P', function (t) {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecjpoint = ECPoint.fromPublicKey(publicKey).toECJPoint()
      var ecpoint = new ECPoint(null, null)
      var result = ecjpoint.mixedAdd(ecpoint)
      t.same(result.x.ucmp(ecjpoint.x), 0)
      t.same(result.y.ucmp(ecjpoint.y), 0)
      t.same(result.z.ucmp(ecjpoint.z), 0)
      t.end()
    })

    t.test('P + P -> 2P', function (t) {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecpoint = ECPoint.fromPublicKey(publicKey)
      var expected = ecpoint.toECJPoint().dbl()
      var result = ecpoint.toECJPoint().mixedAdd(ecpoint)
      t.same(result.x.ucmp(expected.x), 0)
      t.same(result.y.ucmp(expected.y), 0)
      t.same(result.z.ucmp(expected.z), 0)
      t.end()
    })

    t.test('P + (-P) -> O', function (t) {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecpoint = ECPoint.fromPublicKey(publicKey)
      var result = ecpoint.toECJPoint().mixedAdd(ecpoint.neg())
      t.true(result.inf)
      t.end()
    })

    util.repeat(t, 'random tests (add/mixedAdd)', util.env.repeat, function (t) {
      var publicKey1 = util.getPublicKey(util.getPrivateKey()).compressed
      var ecjpoint = ECPoint.fromPublicKey(publicKey1).toECJPoint()
      var publicKey2 = util.getPublicKey(util.getPrivateKey()).compressed
      var ecpoint = ECPoint.fromPublicKey(publicKey2)
      var expected = ecjpoint.add(ecpoint.toECJPoint())
      var result = ecjpoint.mixedAdd(ecpoint)
      t.same(result.x.ucmp(expected.x), 0)
      t.same(result.y.ucmp(expected.y), 0)
      t.same(result.z.ucmp(expected.z), 0)
      t.end()
    })

    t.end()
  })

  t.test('dbl', function (t) {
    t.test('doubling infinity', function (t) {
      var ecjpoint = new ECJPoint(null, null, null)
      t.true(ecjpoint.dbl().inf)
      t.end()
    })

    t.test('2P = 0 (y is same)', function (t) {
      var bn = BN.fromBuffer(util.getMessage())
      var ecjpoint = new ECPoint(bn, BN.fromNumber(0)).toECJPoint()
      t.true(ecjpoint.dbl().inf)
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecjpoint = ECPoint.fromPublicKey(publicKey).toECJPoint()
      var expected = ecjpoint.add(ecjpoint)
      var result = ecjpoint.dbl()
      t.same(result.x.ucmp(expected.x), 0)
      t.same(result.y.ucmp(expected.y), 0)
      t.same(result.z.ucmp(expected.z), 0)
      t.end()
    })

    t.end()
  })

  t.test('dblp', function (t) {
    util.repeat(t, 'random tests (pow from 0 to 10)', util.env.repeat, function (t) {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecjpoint = ECPoint.fromPublicKey(publicKey).toECJPoint()
      for (var i = 0, expected = ecjpoint; i < 10; ++i, expected = expected.dbl()) {
        var result = ecjpoint.dblp(i)
        t.same(result.x.ucmp(expected.x), 0)
        t.same(result.y.ucmp(expected.y), 0)
        t.same(result.z.ucmp(expected.z), 0)
      }

      t.end()
    })

    t.end()
  })

  t.end()
})
