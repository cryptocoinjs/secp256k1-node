'use strict'
var test = require('tape')
var ECPoint = require('../lib/js/ecpoint')
var ECJPoint = require('../lib/js/ecjpoint')
var BN = require('../lib/js/bn')

var util = require('./util')

var pbuf = new Buffer('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 'hex')
var zerobuf = new Buffer('0000000000000000000000000000000000000000000000000000000000000000', 'hex')
var onebuf = new Buffer('0000000000000000000000000000000000000000000000000000000000000001', 'hex')

test('ECPoint', function (t) {
  util.setSeed(util.env.seed)

  t.test('ECPoint.fromPublicKey', function (t) {
    t.test('length from 0 to 100 except 33 and 65', function (t) {
      for (var size = 0; size < 100; ++size) {
        if (size === 33 || size === 65) continue
        var publicKey = new Buffer(size)
        t.same(ECPoint.fromPublicKey(publicKey), null)
      }

      t.end()
    })

    t.test('short key', function (t) {
      t.test('length eq 33, first byte from 0 to 255, but not 2 and 3', function (t) {
        var publicKey = new Buffer(33)
        for (var first = 0; first < 256; ++first) {
          if (first === 0x02 || first === 0x03) continue
          publicKey[0] = first
          t.same(ECPoint.fromPublicKey(publicKey), null)
        }

        t.end()
      })

      t.test('x eq p', function (t) {
        var publicKey = Buffer.concat([new Buffer([0x02]), pbuf])
        t.same(ECPoint.fromPublicKey(publicKey), null)
        t.end()
      })

      t.test('y is quadratic nonresidue', function (t) {
        var publicKey = new Buffer('02fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140', 'hex')
        t.same(ECPoint.fromPublicKey(publicKey), null)
        t.end()
      })

      t.test('0x03 should change y sign', function (t) {
        var p1 = ECPoint.fromPublicKey(Buffer.concat([new Buffer([0x02]), onebuf]))
        var p2 = ECPoint.fromPublicKey(Buffer.concat([new Buffer([0x03]), onebuf]))

        t.notDeepEqual(p1, null)
        t.notDeepEqual(p2, null)
        t.same(p1.x.ucmp(p2.x), 0)
        t.same(p1.y.redNeg().ucmp(p2.y), 0)
        t.end()
      })

      t.end()
    })

    t.test('full key', function (t) {
      t.test('length eq 65, first byte from 0 to 255, but not 4, 6 and 7', function (t) {
        var publicKey = new Buffer(65)
        for (var first = 0; first < 256; ++first) {
          if (first === 0x04 || first === 0x06 || first === 0x07) continue
          publicKey[0] = first
          t.same(ECPoint.fromPublicKey(publicKey), null)
        }

        t.end()
      })

      t.test('x eq p', function (t) {
        var publicKey = Buffer.concat([new Buffer([0x04]), pbuf, zerobuf])
        t.same(ECPoint.fromPublicKey(publicKey), null)
        t.end()
      })

      t.test('y eq p', function (t) {
        var publicKey = Buffer.concat([new Buffer([0x04]), zerobuf, pbuf])
        t.same(ECPoint.fromPublicKey(publicKey), null)
        t.end()
      })

      t.test('first byte is 0x06, y is event', function (t) {
        var publicKey = Buffer.concat([new Buffer([0x06]), zerobuf, zerobuf])
        t.same(ECPoint.fromPublicKey(publicKey), null)
        t.end()
      })

      t.test('first byte is 0x06, y is odd', function (t) {
        var publicKey = Buffer.concat([new Buffer([0x07]), zerobuf, onebuf])
        t.same(ECPoint.fromPublicKey(publicKey), null)
        t.end()
      })

      t.test('x*x*x + 7 != y*y', function (t) {
        var publicKey = Buffer.concat([new Buffer([0x04]), zerobuf, zerobuf])
        t.same(ECPoint.fromPublicKey(publicKey), null)
        t.end()
      })

      t.end()
    })

    t.end()
  })

  t.test('toPublicKey', function (t) {
    t.test('compressed & y is even', function (t) {
      var p = new ECPoint(BN.fromBuffer(zerobuf), BN.fromBuffer(zerobuf))
      var publicKey = p.toPublicKey(true)
      t.same(publicKey, Buffer.concat([new Buffer([0x02]), zerobuf]))
      t.end()
    })

    t.test('compressed & y is odd', function (t) {
      var p = new ECPoint(BN.fromBuffer(zerobuf), BN.fromBuffer(onebuf))
      var publicKey = p.toPublicKey(true)
      t.same(publicKey, Buffer.concat([new Buffer([0x03]), zerobuf]))
      t.end()
    })

    t.test('uncompressed', function (t) {
      var p = new ECPoint(BN.fromBuffer(zerobuf), BN.fromBuffer(zerobuf))
      var publicKey = p.toPublicKey(false)
      t.same(publicKey, Buffer.concat([new Buffer([0x04]), zerobuf, zerobuf]))
      t.end()
    })

    t.end()
  })

  t.test('fromECJPoint/toECJPoint', function (t) {
    t.test('fromECJPoint return infinity for infinity', function (t) {
      var ecjpoint = new ECJPoint(null, null, null)
      var ecpoint = ECPoint.fromECJPoint(ecjpoint)
      t.true(ecpoint.inf)
      t.end()
    })

    t.test('toECJPoint return infinity for infinity', function (t) {
      var ecpoint = new ECPoint(null, null)
      var ecjpoint = ecpoint.toECJPoint()
      t.true(ecjpoint.inf)
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecpoint = ECPoint.fromPublicKey(publicKey)
      var ecpoint2 = ECPoint.fromECJPoint(ecpoint.toECJPoint())
      t.same(ecpoint.x.ucmp(ecpoint2.x), 0)
      t.same(ecpoint.y.ucmp(ecpoint2.y), 0)
      t.end()
    })

    t.end()
  })

  t.test('neg', function (t) {
    t.test('ECPoint, return infinity for infinity', function (t) {
      var ecpoint = new ECPoint(null, null)
      t.true(ecpoint.neg().inf)
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecpoint = ECPoint.fromPublicKey(publicKey)
      var result = ecpoint.neg()
      t.same(result.x.ucmp(ecpoint.x), 0)
      t.same(result.y.ucmp(ecpoint.y.redNeg()), 0)
      t.end()
    })
  })

  t.test('add', function (t) {
    t.test('O + P -> P', function (t) {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecpoint1 = new ECPoint(null, null)
      var ecpoint2 = ECPoint.fromPublicKey(publicKey)
      var result = ecpoint1.add(ecpoint2)
      t.same(result.x.ucmp(ecpoint2.x), 0)
      t.same(result.y.ucmp(ecpoint2.y), 0)
      t.end()
    })

    t.test('P + O -> P', function (t) {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecpoint1 = ECPoint.fromPublicKey(publicKey)
      var ecpoint2 = new ECPoint(null, null)
      var result = ecpoint1.add(ecpoint2)
      t.same(result.x.ucmp(ecpoint1.x), 0)
      t.same(result.y.ucmp(ecpoint1.y), 0)
      t.end()
    })

    t.test('P + P -> 2P', function (t) {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecpoint = ECPoint.fromPublicKey(publicKey)
      var expected = ecpoint.dbl()
      var result = ecpoint.add(ecpoint)
      t.same(result.x.ucmp(expected.x), 0)
      t.same(result.y.ucmp(expected.y), 0)
      t.end()
    })

    t.test('P + (-P) -> O', function (t) {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecpoint = ECPoint.fromPublicKey(publicKey)
      var result = ecpoint.add(ecpoint.neg())
      t.true(result.inf)
      t.end()
    })

    util.repeat(t, 'random tests (compare with ECJPoint)', util.env.repeat, function (t) {
      var publicKey1 = util.getPublicKey(util.getPrivateKey()).compressed
      var ecpoint1 = ECPoint.fromPublicKey(publicKey1)
      var publicKey2 = util.getPublicKey(util.getPrivateKey()).compressed
      var ecpoint2 = ECPoint.fromPublicKey(publicKey2)
      var expected = ECPoint.fromECJPoint(ecpoint1.toECJPoint().add(ecpoint2.toECJPoint()))
      var result = ecpoint1.add(ecpoint2)
      t.same(result.x.ucmp(expected.x), 0)
      t.same(result.y.ucmp(expected.y), 0)
      t.end()
    })

    t.end()
  })

  t.test('dbl', function (t) {
    t.test('doubling infinity', function (t) {
      var ecpoint = new ECPoint(null, null)
      t.true(ecpoint.dbl().inf)
      t.end()
    })

    t.test('2P = 0 (y is same)', function (t) {
      var bn = BN.fromBuffer(util.getMessage())
      var ecpoint = new ECPoint(bn, BN.fromNumber(0))
      t.true(ecpoint.dbl().inf)
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecpoint = ECPoint.fromPublicKey(publicKey)
      var expected = ecpoint.add(ecpoint)
      var result = ecpoint.dbl()
      t.same(result.x.ucmp(expected.x), 0)
      t.same(result.y.ucmp(expected.y), 0)
      t.end()
    })

    t.end()
  })

  t.end()
})
