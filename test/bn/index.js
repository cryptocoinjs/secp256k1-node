'use strict'

var expect = require('chai').expect
var BigNum = require('bignum')

var BN = require('../../lib/js/bn')
var util = require('../util')
var bnUtil = require('./util')

describe('BN', function () {
  this.timeout(util.env.repeat * 25)

  before(function () {
    util.setSeed(util.env.seed)
  })

  describe('fromNumber', function () {
    util.repeatIt('random tests', util.env.repeat, function () {
      var b32 = util.getMessage()
      var num = ((b32[0] << 24) + (b32[1] << 16) + (b32[2] << 8) + b32[3]) & 0x03ffffff
      var bn = BN.fromNumber(num)
      bnUtil.testBN(bn, BigNum(num))
    })
  })

  describe('fromBuffer/toBuffer', function () {
    for (var i = 0; i < 10; ++i) {
      it('all bits in #' + i + ' word', function () {
        var b32 = bnUtil.fillZeros(BigNum.pow(2, 26).sub(1).shiftLeft(26 * i).toBuffer())
        var bn = BN.fromBuffer(b32)
        bnUtil.testBN(bn, BigNum.fromBuffer(b32))
        expect(bn.toBuffer().toString('hex')).to.equal(b32.toString('hex'))
      })
    }

    util.repeatIt('random tests', util.env.repeat, function () {
      var b32 = util.getMessage()
      var bn = BN.fromBuffer(b32)
      bnUtil.testBN(bn, BigNum.fromBuffer(b32))
      expect(bn.toBuffer().toString('hex')).to.equal(b32.toString('hex'))
    })
  })

  describe('isOverflow', function () {
    it('0', function () {
      var bn = BN.fromBuffer(bnUtil.fillZeros(BigNum(0).toBuffer()))
      expect(bn.isOverflow()).to.be.false
    })

    it('n - 1', function () {
      var bn = BN.fromBuffer(bnUtil.fillZeros(bnUtil.N.sub(1).toBuffer()))
      expect(bn.isOverflow()).to.be.false
    })

    it('n', function () {
      var bn = BN.fromBuffer(bnUtil.fillZeros(bnUtil.N.toBuffer()))
      expect(bn.isOverflow()).to.be.true
    })

    it('n + 1', function () {
      var bn = BN.fromBuffer(bnUtil.fillZeros(bnUtil.N.add(1).toBuffer()))
      expect(bn.isOverflow()).to.be.true
    })

    util.repeatIt('random tests', util.env.repeat, function () {
      var b32 = util.getMessage()
      var bn = BN.fromBuffer(b32)
      expect(bn.isOverflow()).to.equal(bnUtil.N.cmp(BigNum.fromBuffer(b32)) <= 0)
    })
  })

  describe('isHigh', function () {
    it('0', function () {
      var bn = BN.fromBuffer(bnUtil.fillZeros(BigNum(0).toBuffer()))
      expect(bn.isHigh()).to.be.false
    })

    it('nh - 1', function () {
      var bn = BN.fromBuffer(bnUtil.fillZeros(bnUtil.NH.sub(1).toBuffer()))
      expect(bn.isHigh()).to.be.false
    })

    it('nh', function () {
      var bn = BN.fromBuffer(bnUtil.fillZeros(bnUtil.NH.toBuffer()))
      expect(bn.isHigh()).to.be.false
    })

    it('nh + 1', function () {
      var bn = BN.fromBuffer(bnUtil.fillZeros(bnUtil.NH.add(1).toBuffer()))
      expect(bn.isHigh()).to.be.true
    })

    util.repeatIt('random tests', util.env.repeat, function () {
      var b32 = util.getMessage()
      var bn = BN.fromBuffer(b32)
      expect(bn.isHigh()).to.equal(bnUtil.NH.cmp(BigNum.fromBuffer(b32)) <= 0)
    })
  })

  describe('add', function () {
    util.repeatIt('random tests', util.env.repeat, function () {
      var b32A = util.getMessage()
      var b32B = util.getTweak()
      var bnR = BigNum.fromBuffer(b32A).add(BigNum.fromBuffer(b32B))

      var a = BN.fromBuffer(b32A)
      var b = BN.fromBuffer(b32B)
      var r = a.add(b)

      bnUtil.testBN(r, bnR)
    })
  })

  describe('sub', function () {
    util.repeatIt('random tests', util.env.repeat, function () {
      var b32A = util.getMessage()
      var b32B = util.getTweak()
      var bnR = BigNum.fromBuffer(b32A).sub(BigNum.fromBuffer(b32B))

      var a = BN.fromBuffer(b32A)
      var b = BN.fromBuffer(b32B)
      var r = a.sub(b)

      bnUtil.testBN(r, bnR)
    })
  })

  describe('umul', function () {
    util.repeatIt('random tests', util.env.repeat, function () {
      var b32A = util.getMessage()
      var b32B = util.getTweak()
      var bnR = BigNum.fromBuffer(b32A).mul(BigNum.fromBuffer(b32B))

      var a = BN.fromBuffer(b32A)
      var b = BN.fromBuffer(b32B)
      var r = a.umul(b)

      bnUtil.testBN(r, bnR)
    })
  })

  describe('ureduce', function () {
    util.repeatIt('random tests', util.env.repeat, function () {
      var b32A = util.getMessage()
      var b32B = util.getTweak()
      var bnR = BigNum.fromBuffer(b32A).mul(BigNum.fromBuffer(b32B)).mod(bnUtil.N)

      var a = BN.fromBuffer(b32A)
      var b = BN.fromBuffer(b32B)
      var r = a.umul(b).ureduce()

      bnUtil.testBN(r, bnR)
    })
  })

  describe('uinvm', function () {
    util.repeatIt('random tests', util.env.repeat, function () {
      var b32 = util.getMessage()
      bnUtil.testBN(BN.fromBuffer(b32).uinvm(), BigNum.fromBuffer(b32).invertm(bnUtil.N))
    })
  })

  describe('redNeg', function () {
    it('0 -> 0', function () {
      var bn = BN.fromBuffer(bnUtil.fillZeros(BigNum(0).toBuffer()))
      bnUtil.testBN(bn.redNeg(), BigNum(0))
    })

    it('1 -> p - 1', function () {
      var bn = BN.fromBuffer(bnUtil.fillZeros(BigNum(1).toBuffer()))
      bnUtil.testBN(bn.redNeg(), bnUtil.P.sub(1))
    })

    it('p - 1 -> 1', function () {
      var bn = BN.fromBuffer(bnUtil.fillZeros(bnUtil.P.sub(1).toBuffer()))
      bnUtil.testBN(bn.redNeg(), BigNum(1))
    })

    util.repeatIt('random tests', util.env.repeat, function () {
      var bn = BN.fromBuffer(util.getMessage())
      if (bn.ucmp(BN.p) >= 0) { bn._redIReduce() }

      bnUtil.testBN(bn.redNeg(), bnUtil.P.sub(BigNum.fromBuffer(bn.toBuffer())))
    })
  })

  describe('redAdd', function () {
    it('(p - 2) + 1 -> p - 1', function () {
      var a = BN.fromBuffer(bnUtil.fillZeros(bnUtil.P.sub(2).toBuffer()))
      var b = BN.fromBuffer(bnUtil.fillZeros(BigNum(1).toBuffer()))
      bnUtil.testBN(a.redAdd(b), bnUtil.P.sub(1))
    })

    it('(p - 1) + 1 -> 0', function () {
      var a = BN.fromBuffer(bnUtil.fillZeros(bnUtil.P.sub(1).toBuffer()))
      var b = BN.fromBuffer(bnUtil.fillZeros(BigNum(1).toBuffer()))
      bnUtil.testBN(a.redAdd(b), BigNum(0))
    })

    it('(p - 1) + 2 -> 1', function () {
      var a = BN.fromBuffer(bnUtil.fillZeros(bnUtil.P.sub(1).toBuffer()))
      var b = BN.fromBuffer(bnUtil.fillZeros(BigNum(2).toBuffer()))
      bnUtil.testBN(a.redAdd(b), BigNum(1))
    })

    it('(p - 1) + (p - 1) -> p - 2', function () {
      var a = BN.fromBuffer(bnUtil.fillZeros(bnUtil.P.sub(1).toBuffer()))
      var b = BN.fromBuffer(bnUtil.fillZeros(bnUtil.P.sub(1).toBuffer()))
      bnUtil.testBN(a.redAdd(b), bnUtil.P.sub(2))
    })

    util.repeatIt('random tests', util.env.repeat, function () {
      var a = BN.fromBuffer(util.getMessage())
      var b = BN.fromBuffer(util.getTweak())
      bnUtil.testBN(a.redAdd(b), BigNum.fromBuffer(a.toBuffer()).add(BigNum.fromBuffer(b.toBuffer())).mod(bnUtil.P))
    })
  })

  describe('redMul', function () {
    util.repeatIt('random tests', util.env.repeat, function () {
      var a = BN.fromBuffer(util.getMessage())
      if (a.ucmp(BN.p) >= 0) { a._redIReduce() }
      var b = BN.fromBuffer(util.getTweak())
      if (b.ucmp(BN.p) >= 0) { b._redIReduce() }

      var bnA = BigNum.fromBuffer(a.toBuffer())
      var bnB = BigNum.fromBuffer(b.toBuffer())
      bnUtil.testBN(a.redMul(b), bnA.mul(bnB).mod(bnUtil.P))
    })
  })

  describe('redInvm', function () {
    util.repeatIt('random tests', util.env.repeat, function () {
      var b32 = util.getMessage()
      var a = BN.fromBuffer(b32)
      if (a.ucmp(BN.p) >= 0) { a._redIReduce() }

      bnUtil.testBN(a.redInvm(), BigNum.fromBuffer(a.toBuffer()).invertm(bnUtil.P))
    })
  })
})
