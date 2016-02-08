'use strict'

var expect = require('chai').expect
var ECPoint = require('../lib/js/ecpoint')
var ECJPoint = require('../lib/js/ecjpoint')
var BN = require('../lib/js/bn')

var util = require('./util')

var pbuf = new Buffer('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 'hex')
var zerobuf = new Buffer('0000000000000000000000000000000000000000000000000000000000000000', 'hex')
var onebuf = new Buffer('0000000000000000000000000000000000000000000000000000000000000001', 'hex')

describe('ECPoint', function () {
  before(function () {
    util.setSeed(util.env.seed)
  })

  describe('ECPoint.fromPublicKey', function () {
    it('length from 0 to 100 except 33 and 65', function () {
      for (var size = 0; size < 100; ++size) {
        if (size === 33 || size === 65) {
          continue
        }

        var publicKey = new Buffer(size)
        expect(ECPoint.fromPublicKey(publicKey)).to.be.null
      }
    })

    describe('short key', function () {
      it('length eq 33, first byte from 0 to 255, but not 2 and 3', function () {
        var publicKey = new Buffer(33)
        for (var first = 0; first < 256; ++first) {
          if (first === 0x02 || first === 0x03) {
            continue
          }

          publicKey[0] = first
          expect(ECPoint.fromPublicKey(publicKey)).to.be.null
        }
      })

      it('x eq p', function () {
        var publicKey = Buffer.concat([new Buffer([0x02]), pbuf])
        expect(ECPoint.fromPublicKey(publicKey)).to.be.null
      })

      it('y is quadratic nonresidue', function () {
        var publicKey = new Buffer('02fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140', 'hex')
        expect(ECPoint.fromPublicKey(publicKey)).to.be.null
      })

      it('0x03 should change y sign', function () {
        var p1 = ECPoint.fromPublicKey(Buffer.concat([new Buffer([0x02]), onebuf]))
        var p2 = ECPoint.fromPublicKey(Buffer.concat([new Buffer([0x03]), onebuf]))

        expect(p1).to.be.not.null
        expect(p2).to.be.not.null
        expect(p1.x.ucmp(p2.x)).to.equal(0)
        expect(p1.y.redNeg().ucmp(p2.y)).to.equal(0)
      })
    })

    describe('full key', function () {
      it('length eq 65, first byte from 0 to 255, but not 4, 6 and 7', function () {
        var publicKey = new Buffer(65)
        for (var first = 0; first < 256; ++first) {
          if (first === 0x04 || first === 0x06 || first === 0x07) {
            continue
          }

          publicKey[0] = first
          expect(ECPoint.fromPublicKey(publicKey)).to.be.null
        }
      })

      it('x eq p', function () {
        var publicKey = Buffer.concat([new Buffer([0x04]), pbuf, zerobuf])
        expect(ECPoint.fromPublicKey(publicKey)).to.be.null
      })

      it('y eq p', function () {
        var publicKey = Buffer.concat([new Buffer([0x04]), zerobuf, pbuf])
        expect(ECPoint.fromPublicKey(publicKey)).to.be.null
      })

      it('first byte is 0x06, y is event', function () {
        var publicKey = Buffer.concat([new Buffer([0x06]), zerobuf, zerobuf])
        expect(ECPoint.fromPublicKey(publicKey)).to.be.null
      })

      it('first byte is 0x06, y is odd', function () {
        var publicKey = Buffer.concat([new Buffer([0x07]), zerobuf, onebuf])
        expect(ECPoint.fromPublicKey(publicKey)).to.be.null
      })

      it('x*x*x + 7 != y*y', function () {
        var publicKey = Buffer.concat([new Buffer([0x04]), zerobuf, zerobuf])
        expect(ECPoint.fromPublicKey(publicKey)).to.be.null
      })
    })
  })

  describe('toPublicKey', function () {
    it('compressed & y is even', function () {
      var p = new ECPoint(BN.fromBuffer(zerobuf), BN.fromBuffer(zerobuf))
      var publicKey = p.toPublicKey(true)
      expect(publicKey.toString('hex')).to.equal(Buffer.concat([new Buffer([0x02]), zerobuf]).toString('hex'))
    })

    it('compressed & y is odd', function () {
      var p = new ECPoint(BN.fromBuffer(zerobuf), BN.fromBuffer(onebuf))
      var publicKey = p.toPublicKey(true)
      expect(publicKey.toString('hex')).to.equal(Buffer.concat([new Buffer([0x03]), zerobuf]).toString('hex'))
    })

    it('uncompressed', function () {
      var p = new ECPoint(BN.fromBuffer(zerobuf), BN.fromBuffer(zerobuf))
      var publicKey = p.toPublicKey(false)
      expect(publicKey.toString('hex')).to.equal(Buffer.concat([new Buffer([0x04]), zerobuf, zerobuf]).toString('hex'))
    })
  })

  describe('fromECJPoint/toECJPoint', function () {
    it('fromECJPoint return infinity for infinity', function () {
      var ecjpoint = new ECJPoint(null, null, null)
      var ecpoint = ECPoint.fromECJPoint(ecjpoint)
      expect(ecpoint.inf).to.be.true
    })

    it('toECJPoint return infinity for infinity', function () {
      var ecpoint = new ECPoint(null, null)
      var ecjpoint = ecpoint.toECJPoint()
      expect(ecjpoint.inf).to.be.true
    })

    util.repeatIt('random tests', util.env.repeat, function () {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecpoint = ECPoint.fromPublicKey(publicKey)
      var ecpoint2 = ECPoint.fromECJPoint(ecpoint.toECJPoint())
      expect(ecpoint.x.ucmp(ecpoint2.x)).to.equal(0)
      expect(ecpoint.y.ucmp(ecpoint2.y)).to.equal(0)
    })
  })

  describe('neg', function () {
    it('ECPoint, return infinity for infinity', function () {
      var ecpoint = new ECPoint(null, null)
      expect(ecpoint.neg().inf).to.be.true
    })

    util.repeatIt('random tests', util.env.repeat, function () {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecpoint = ECPoint.fromPublicKey(publicKey)
      var result = ecpoint.neg()
      expect(result.x.ucmp(ecpoint.x)).to.equal(0)
      expect(result.y.ucmp(ecpoint.y.redNeg())).to.equal(0)
    })
  })

  describe('add', function () {
    it('O + P -> P', function () {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecpoint1 = new ECPoint(null, null)
      var ecpoint2 = ECPoint.fromPublicKey(publicKey)
      var result = ecpoint1.add(ecpoint2)
      expect(result.x.ucmp(ecpoint2.x)).to.equal(0)
      expect(result.y.ucmp(ecpoint2.y)).to.equal(0)
    })

    it('P + O -> P', function () {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecpoint1 = ECPoint.fromPublicKey(publicKey)
      var ecpoint2 = new ECPoint(null, null)
      var result = ecpoint1.add(ecpoint2)
      expect(result.x.ucmp(ecpoint1.x)).to.equal(0)
      expect(result.y.ucmp(ecpoint1.y)).to.equal(0)
    })

    it('P + P -> 2P', function () {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecpoint = ECPoint.fromPublicKey(publicKey)
      var expected = ecpoint.dbl()
      var result = ecpoint.add(ecpoint)
      expect(result.x.ucmp(expected.x)).to.equal(0)
      expect(result.y.ucmp(expected.y)).to.equal(0)
    })

    it('P + (-P) -> O', function () {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecpoint = ECPoint.fromPublicKey(publicKey)
      var result = ecpoint.add(ecpoint.neg())
      expect(result.inf).to.be.true
    })

    util.repeatIt('random tests (compare with ECJPoint)', util.env.repeat, function () {
      var publicKey1 = util.getPublicKey(util.getPrivateKey()).compressed
      var ecpoint1 = ECPoint.fromPublicKey(publicKey1)
      var publicKey2 = util.getPublicKey(util.getPrivateKey()).compressed
      var ecpoint2 = ECPoint.fromPublicKey(publicKey2)
      var expected = ECPoint.fromECJPoint(ecpoint1.toECJPoint().add(ecpoint2.toECJPoint()))
      var result = ecpoint1.add(ecpoint2)
      expect(result.x.ucmp(expected.x)).to.equal(0)
      expect(result.y.ucmp(expected.y)).to.equal(0)
    })
  })

  describe('dbl', function () {
    it('doubling infinity', function () {
      var ecpoint = new ECPoint(null, null)
      expect(ecpoint.dbl().inf).to.be.true
    })

    it('2P = 0 (y is same)', function () {
      var bn = BN.fromBuffer(util.getMessage())
      var ecpoint = new ECPoint(bn, BN.fromNumber(0))
      expect(ecpoint.dbl().inf).to.be.true
    })

    util.repeatIt('random tests', util.env.repeat, function () {
      var publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      var ecpoint = ECPoint.fromPublicKey(publicKey)
      var expected = ecpoint.add(ecpoint)
      var result = ecpoint.dbl()
      expect(result.x.ucmp(expected.x)).to.equal(0)
      expect(result.y.ucmp(expected.y)).to.equal(0)
    })
  })
})
