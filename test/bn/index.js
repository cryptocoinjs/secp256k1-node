'use strict'
/* global before, describe, it */

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
    it('0', function () {
      var bn = BN.fromNumber(0)
      bnUtil.testBN(bn, BigNum(0))
    })

    it('2**26-1', function () {
      var bn = BN.fromNumber(0x03ffffff)
      bnUtil.testBN(bn, BigNum(0x03ffffff))
    })

    it('2**26 should equal 0', function () {
      var bn = BN.fromNumber(0x04000000)
      bnUtil.testBN(bn, BigNum(0))
    })

    util.repeatIt('random tests', util.env.repeat, function () {
      var b32 = util.getMessage()
      var num = ((b32[0] << 24) + (b32[1] << 16) + (b32[2] << 8) + b32[3]) & 0x03ffffff
      var bn = BN.fromNumber(num)
      bnUtil.testBN(bn, BigNum(num))
    })
  })

  describe('fromBuffer/toBuffer', function () {
    for (var i = 0; i < 10; ++i) {
      it('all bits eq 1 in #' + i + ' word', function () {
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

  describe.skip('clone', function () {})

  describe('strip', function () {
    it('[0] -> [0]', function () {
      var bn = new BN()
      bn.words = [0]
      bn.length = 1
      bnUtil.testBN(bn.strip(), BigNum(0))
    })

    it('[1] -> [1]', function () {
      var bn = new BN()
      bn.words = [1]
      bn.length = 1
      bnUtil.testBN(bn.strip(), BigNum(1))
    })

    it('[0, 0] -> [0]', function () {
      var bn = new BN()
      bn.words = [0, 0]
      bn.length = 2
      bnUtil.testBN(bn.strip(), BigNum(0))
    })

    it('[1, 0] -> [1]', function () {
      var bn = new BN()
      bn.words = [1, 0]
      bn.length = 2
      bnUtil.testBN(bn.strip(), BigNum(1))
    })
  })

  describe('normSign', function () {
    it('1 -> 1', function () {
      var bn = BN.fromNumber(1)
      bnUtil.testBN(bn.normSign(), BigNum(1))
    })

    it('-1 -> -1', function () {
      var bn = BN.fromNumber(1)
      bn.negative = 1
      bnUtil.testBN(bn.normSign(), BigNum(-1))
    })

    it('0 -> 0', function () {
      var bn = BN.fromNumber(0)
      bnUtil.testBN(bn.normSign(), BigNum(0))
    })

    it('-0 -> 0', function () {
      var bn = BN.fromNumber(0)
      bn.negative = 1
      bnUtil.testBN(bn.normSign(), BigNum(0))
    })

    it('0x04000000 -> 0x04000000', function () {
      var b32 = bnUtil.fillZeros(new Buffer([0xff, 0xff, 0xff, 0xff]))
      var bn = BN.fromBuffer(b32)
      bnUtil.testBN(bn.normSign(), BigNum.fromBuffer(b32))
    })

    it('-0x04000000 -> -0x04000000', function () {
      var b32 = bnUtil.fillZeros(new Buffer([0xff, 0xff, 0xff, 0xff]))
      var bn = BN.fromBuffer(b32)
      bn.negative = 1
      bnUtil.testBN(bn.normSign(), BigNum.fromBuffer(b32).neg())
    })
  })

  describe('isEven', function () {
    it('[0] -> true', function () {
      expect(BN.fromNumber(0).isEven()).to.be.true
    })

    it('[1] -> false', function () {
      expect(BN.fromNumber(1).isEven()).to.be.false
    })
  })

  describe('isOdd', function () {
    it('[0] -> false', function () {
      expect(BN.fromNumber(0).isOdd()).to.be.false
    })

    it('[1] -> true', function () {
      expect(BN.fromNumber(1).isOdd()).to.be.true
    })
  })

  describe('isZero', function () {
    it('[0] -> true', function () {
      expect(BN.fromNumber(0).isZero()).to.be.true
    })

    it('[1] -> false', function () {
      expect(BN.fromNumber(1).isZero()).to.be.false
    })
  })

  describe('ucmp', function () {
    it('a.length > b.length', function () {
      var a = new BN()
      a.length = 2
      var b = new BN()
      b.length = 1
      expect(a.ucmp(b)).to.equal(1)
    })

    it('a.length < b.length', function () {
      var a = new BN()
      a.length = 1
      var b = new BN()
      b.length = 2
      expect(a.ucmp(b)).to.equal(-1)
    })

    it('[2] > [1]', function () {
      var a = BN.fromNumber(2)
      var b = BN.fromNumber(1)
      expect(a.ucmp(b)).to.equal(1)
    })

    it('[1] < [2]', function () {
      var a = BN.fromNumber(1)
      var b = BN.fromNumber(2)
      expect(a.ucmp(b)).to.equal(-1)
    })

    it('[1] = [1]', function () {
      var a = BN.fromNumber(1)
      var b = BN.fromNumber(1)
      expect(a.ucmp(b)).to.equal(0)
    })

    it('-2 > 1', function () {
      var a = BN.fromNumber(2)
      a.negative = 1
      var b = BN.fromNumber(1)
      expect(a.ucmp(b)).to.equal(1)
    })

    it('1 < -2', function () {
      var a = BN.fromNumber(1)
      var b = BN.fromNumber(2)
      b.negative = 1
      expect(a.ucmp(b)).to.equal(-1)
    })

    it('-1 = -1', function () {
      var a = BN.fromNumber(1)
      a.negative = 1
      var b = BN.fromNumber(1)
      b.negative = 1
      expect(a.ucmp(b)).to.equal(0)
    })

    util.repeatIt('random tests', util.env.repeat, function () {
      var b32a = util.getMessage()
      var b32b = util.getTweak()
      var a = BN.fromBuffer(b32a)
      var b = BN.fromBuffer(b32b)
      expect(a.ucmp(b)).to.equal(BigNum.fromBuffer(b32a).cmp(BigNum.fromBuffer(b32b)))
    })
  })

  describe('gtOne', function () {
    it('0', function () {
      var bn = BN.fromNumber(0)
      expect(bn.gtOne()).to.be.false
    })

    it('1', function () {
      var bn = BN.fromNumber(1)
      expect(bn.gtOne()).to.be.false
    })

    it('2', function () {
      var bn = BN.fromNumber(2)
      expect(bn.gtOne()).to.be.true
    })

    it('length > 1', function () {
      var bn = new BN()
      bn.length = 2
      expect(bn.gtOne()).to.be.true
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

  describe('bitLengthGT256', function () {
    it('length eq 9', function () {
      var bn = new BN()
      bn.length = 9
      expect(bn.bitLengthGT256()).to.be.false
    })

    it('length eq 10 and last word is 0x003fffff', function () {
      var bn = new BN()
      bn.words = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0x003fffff]
      bn.length = 10
      expect(bn.bitLengthGT256()).to.be.false
    })

    it('length eq 10 and last word is 0x00400000', function () {
      var bn = new BN()
      bn.words = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00400000]
      bn.length = 10
      expect(bn.bitLengthGT256()).to.be.true
    })

    it('length eq 11', function () {
      var bn = new BN()
      bn.length = 11
      expect(bn.bitLengthGT256()).to.be.true
    })
  })

  describe('iuaddn', function () {
    it('1 + 1', function () {
      var bn = BN.fromNumber(1)
      bnUtil.testBN(bn.iuaddn(1), BigNum(2))
    })

    it('0x03ffffff + 1', function () {
      var bn = BN.fromNumber(0x03ffffff)
      bnUtil.testBN(bn.iuaddn(1), BigNum(0x04000000))
    })

    util.repeatIt('random tests', util.env.repeat, function () {
      var b32 = util.getMessage()
      b32[0] = 0
      var bn = BN.fromBuffer(b32)
      var x = ((b32[1] << 24) + (b32[2] << 16) + (b32[3] << 8) + b32[4]) & 0x03ffffff
      bnUtil.testBN(bn.iuaddn(x), BigNum.fromBuffer(b32).add(x))
    })
  })

  describe('iadd', function () {
    util.repeatIt('random tests', util.env.repeat, function () {
      var b32A = util.getMessage()
      var b32B = util.getTweak()

      var a = BN.fromBuffer(b32A)
      var ac = a.clone()
      var b = BN.fromBuffer(b32B)

      // a + b
      bnUtil.testBN(a.iadd(b), BigNum.fromBuffer(b32A).add(BigNum.fromBuffer(b32B)))
      a.words = ac.clone().words
      a.length = ac.length
      a.negative = 1
      // (-a) + b
      bnUtil.testBN(a.iadd(b), BigNum.fromBuffer(b32A).neg().add(BigNum.fromBuffer(b32B)))
      a.words = ac.clone().words
      a.length = ac.length
      a.negative = 1
      b.negative = 1
      // (-a) + (-b)
      bnUtil.testBN(a.iadd(b), BigNum.fromBuffer(b32A).neg().add(BigNum.fromBuffer(b32B).neg()))
      a.words = ac.clone().words
      a.length = ac.length
      a.negative = 0
      // a + (-b)
      bnUtil.testBN(a.iadd(b), BigNum.fromBuffer(b32A).add(BigNum.fromBuffer(b32B).neg()))
    })
  })

  describe('add', function () {
    it('source was not affected', function () {
      var b32a = util.getMessage()
      var b32b = util.getTweak()

      var a = BN.fromBuffer(b32a)
      var b = BN.fromBuffer(b32b)

      bnUtil.testBN(a.add(b), BigNum.fromBuffer(b32a).add(BigNum.fromBuffer(b32b)))
      expect(a.toBuffer().toString('hex')).to.equal(b32a.toString('hex'))
    })
  })

  describe('isub', function () {
    util.repeatIt('random tests', util.env.repeat, function () {
      var b32A = util.getMessage()
      var b32B = util.getTweak()

      var a = BN.fromBuffer(b32A)
      var ac = a.clone()
      var b = BN.fromBuffer(b32B)

      // a - b
      bnUtil.testBN(a.isub(b), BigNum.fromBuffer(b32A).sub(BigNum.fromBuffer(b32B)))
      a.words = ac.clone().words
      a.length = ac.length
      a.negative = 1
      // (-a) + b
      bnUtil.testBN(a.isub(b), BigNum.fromBuffer(b32A).neg().sub(BigNum.fromBuffer(b32B)))
      a.words = ac.clone().words
      b.negative = 1
      a.length = ac.length
      // (-a) + (-b)
      bnUtil.testBN(a.isub(b), BigNum.fromBuffer(b32A).neg().sub(BigNum.fromBuffer(b32B).neg()))
      a.words = ac.clone().words
      a.negative = 0
      // a + (-b)
      a.length = ac.length
      bnUtil.testBN(a.isub(b), BigNum.fromBuffer(b32A).sub(BigNum.fromBuffer(b32B).neg()))
    })
  })

  describe('sub', function () {
    it('source was not affected', function () {
      var b32a = util.getMessage()
      var b32b = util.getTweak()

      var a = BN.fromBuffer(b32a)
      var b = BN.fromBuffer(b32b)

      bnUtil.testBN(a.sub(b), BigNum.fromBuffer(b32a).sub(BigNum.fromBuffer(b32b)))
      expect(a.toBuffer().toString('hex')).to.equal(b32a.toString('hex'))
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

  describe('umul', function () {
    var out = BN.fromNumber(0)

    describe('umulnTo', function () {
      it('[0x03ffffff] * 0', function () {
        BN.umulnTo(BN.fromNumber(0x03ffffff), 0, out)
        bnUtil.testBN(out, BigNum(0))
      })

      it('[0x03ffffff] * 0x03ffffff', function () {
        BN.umulnTo(BN.fromNumber(0x03ffffff), 0x03ffffff, out)
        bnUtil.testBN(out, BigNum(0x03ffffff).mul(0x03ffffff))
      })

      it('[0x03ffffff, 0x03ffffff] * 0x03ffffff', function () {
        var bn = new BN()
        bn.words = [0x03ffffff, 0x03ffffff]
        bn.length = 2
        BN.umulnTo(bn, 0x03ffffff, out)
        bnUtil.testBN(out, BigNum.fromBuffer(bn.toBuffer()).mul(0x03ffffff))
      })
    })

    describe('umulTo', function () {
      util.repeatIt('random tests', util.env.repeat, function () {
        var b32a = util.getMessage()
        var b32b = util.getTweak()

        var a = BN.fromBuffer(b32a)
        a.length = b32a[0] % 8 + 2 // in [1,9]
        var b = BN.fromBuffer(b32b)
        b.length = b32b[0] % 8 + 2 // in [1,9]

        BN.umulTo(a, b, out)
        bnUtil.testBN(out, BigNum.fromBuffer(a.toBuffer()).mul(BigNum.fromBuffer(b.toBuffer())))
      })
    })

    describe('10x * 10x', function () {
      var min = BigNum(1).shiftLeft(235).sub(1)
      var bnMin = BN.fromBuffer(bnUtil.fillZeros(min.toBuffer()))
      var max = BigNum(1).shiftLeft(256).sub(1)
      var bnMax = BN.fromBuffer(max.toBuffer())

      function test (descripion, fn) {
        describe(descripion, function () {
          it('min * min', function () {
            fn(bnMin, bnMin, out)
            bnUtil.testBN(out, min.mul(min))
          })

          it('min * max', function () {
            fn(bnMin, bnMax, out)
            bnUtil.testBN(out, min.mul(max))
          })

          it('max * min', function () {
            fn(bnMax, bnMin, out)
            bnUtil.testBN(out, max.mul(min))
          })

          it('max * max', function () {
            fn(bnMax, bnMax, out)
            bnUtil.testBN(out, max.mul(max))
          })

          util.repeatIt('random tests', util.env.repeat, function () {
            var a
            var b
            while (!a || !b || a.length !== 10 || b.length !== 10) {
              a = BN.fromBuffer(util.getMessage())
              b = BN.fromBuffer(util.getTweak())
            }

            BN.umulTo(a, b, out)
            bnUtil.testBN(out, BigNum.fromBuffer(a.toBuffer()).mul(BigNum.fromBuffer(b.toBuffer())))
          })
        })
      }

      test('optimized', require('../../lib/js/bn/optimized').umulTo10x10)
      test('umulTo', BN.umulTo)
    })
  })

  describe('isplit', function () {
    it('from 0 to 512 bits', function () {
      var tmp = new BN()
      tmp.words = new Array(10)
      var bignum256 = BigNum(1).shiftLeft(256).sub(1)

      for (var i = 0; i <= 512; ++i) {
        var bignum = BigNum(1).shiftLeft(i).sub(1)
        var bn = BN.fromNumber(0)
        bn.length = Math.max(Math.ceil(bignum.bitLength() / 26), 1)
        for (var j = 0, bign = bignum; j < bn.length; ++j, bign = bign.shiftRight(26)) {
          bn.words[j] = bign.and(0x03ffffff).toNumber()
        }

        bn.isplit(tmp)
        bnUtil.testBN(tmp, bignum.and(bignum256))
        bnUtil.testBN(bn, bignum.shiftRight(256))
      }
    })
  })

  describe('fireduce', function () {
    it('n - 1 -> n - 1', function () {
      var bn = BN.fromBuffer(bnUtil.N.sub(1).toBuffer())
      bnUtil.testBN(bn.fireduce(), bnUtil.N.sub(1))
    })

    it('n -> 0', function () {
      var bn = BN.fromBuffer(bnUtil.N.toBuffer())
      bnUtil.testBN(bn.fireduce(), BigNum(0))
    })

    it('2*n - 1 -> n - 1', function () {
      var bn = BN.umulnTo(BN.fromBuffer(bnUtil.N.toBuffer()), 2, BN.fromNumber(0)).isub(BN.fromNumber(1))
      bnUtil.testBN(bn.fireduce(), bnUtil.N.sub(1))
    })

    it('2*n -> n', function () {
      var bn = BN.umulnTo(BN.fromBuffer(bnUtil.N.toBuffer()), 2, BN.fromNumber(0))
      bnUtil.testBN(bn.fireduce(), bnUtil.N)
    })
  })

  describe('ureduce', function () {
    it('n - 1 -> n - 1', function () {
      var bn = BN.fromBuffer(bnUtil.N.sub(1).toBuffer())
      bnUtil.testBN(bn.ureduce(), bnUtil.N.sub(1))
    })

    it('n -> 0', function () {
      var bn = BN.fromBuffer(bnUtil.N.toBuffer())
      bnUtil.testBN(bn.ureduce(), BigNum(0))
    })

    it('n*n - 1 -> n - 1', function () {
      var bn = BN.fromBuffer(bnUtil.N.toBuffer())
      bnUtil.testBN(bn.umul(bn).sub(BN.fromNumber(1)).ureduce(), bnUtil.N.sub(1))
    })

    util.repeatIt('random tests', util.env.repeat, function () {
      var b32a = util.getMessage()
      var b32b = util.getTweak()

      var a = BN.fromBuffer(b32a)
      var b = BN.fromBuffer(b32b)

      bnUtil.testBN(a.umul(b).ureduce(), BigNum.fromBuffer(b32a).mul(BigNum.fromBuffer(b32b)).mod(bnUtil.N))
    })
  })

  describe('ishrn', function () {
    it('51 bits eq 1, shift from 0 to 26', function () {
      var b32 = bnUtil.fillZeros(new Buffer('07ffffffffffff', 'hex'))
      for (var i = 0; i < 26; ++i) {
        bnUtil.testBN(BN.fromBuffer(b32).ishrn(i), BigNum.fromBuffer(b32).shiftRight(i))
      }
    })

    it('256 bits eq 1, shift from 0 to 26', function () {
      var b32 = new Buffer(32)
      b32.fill(0xff)
      for (var i = 0; i < 26; ++i) {
        bnUtil.testBN(BN.fromBuffer(b32).ishrn(i), BigNum.fromBuffer(b32).shiftRight(i))
      }
    })

    util.repeatIt('random tests', util.env.repeat, function () {
      var b32 = util.getMessage()
      var shift = b32[0] % 26
      bnUtil.testBN(BN.fromBuffer(b32).ishrn(shift), BigNum.fromBuffer(b32).shiftRight(shift))
    })
  })

  describe('uinvm', function () {
    it('0', function () {
      bnUtil.testBN(BN.fromNumber(0).uinvm(), BigNum(0).invertm(bnUtil.N))
    })

    it('n - 1', function () {
      var b32 = bnUtil.N.sub(1).toBuffer()
      bnUtil.testBN(BN.fromBuffer(b32).uinvm(), BigNum.fromBuffer(b32).invertm(bnUtil.N))
    })

    util.repeatIt('random tests', util.env.repeat, function () {
      var b32 = util.getMessage()
      bnUtil.testBN(BN.fromBuffer(b32).uinvm(), BigNum.fromBuffer(b32).invertm(bnUtil.N))
    })
  })

  describe('imulK', function () {
    util.repeatIt('random tests', util.env.repeat, function () {
      var b32 = util.getMessage()
      var bn = BN.fromBuffer(b32)
      bnUtil.testBN(bn.imulK(), BigNum.fromBuffer(b32).mul(bnUtil.K))
    })
  })

  describe('redIReduce', function () {
    it('p - 1 -> p - 1', function () {
      var bn = BN.fromBuffer(bnUtil.P.sub(1).toBuffer())
      bnUtil.testBN(bn.redIReduce(), bnUtil.P.sub(1))
    })

    it('p -> 0', function () {
      var bn = BN.fromBuffer(bnUtil.P.toBuffer())
      bnUtil.testBN(bn.redIReduce(), BigNum(0))
    })

    it('p*p - 1 -> p - 1', function () {
      var bn = BN.fromBuffer(bnUtil.P.toBuffer())
      bnUtil.testBN(bn.umul(bn).sub(BN.fromNumber(1)).redIReduce(), bnUtil.P.sub(1))
    })

    util.repeatIt('random tests', util.env.repeat, function () {
      var a = BN.fromBuffer(util.getMessage())
      if (a.ucmp(BN.p) >= 0) { a.redIReduce() }
      var b = BN.fromBuffer(util.getTweak())
      if (b.ucmp(BN.p) >= 0) { b.redIReduce() }

      var abn = BigNum.fromBuffer(a.toBuffer())
      var bbn = BigNum.fromBuffer(b.toBuffer())
      bnUtil.testBN(a.umul(b).redIReduce(), abn.mul(bbn).mod(bnUtil.P))
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
      if (bn.ucmp(BN.p) >= 0) { bn.redIReduce() }

      bnUtil.testBN(bn.redNeg(), bnUtil.P.sub(BigNum.fromBuffer(bn.toBuffer())))
    })
  })

  describe('redAdd', function () {
    it('source was not affected', function () {
      var a = BN.fromBuffer(util.getMessage())
      if (a.ucmp(BN.p) >= 0) { a.redIReduce() }
      var b = BN.fromBuffer(util.getTweak())
      if (b.ucmp(BN.p) >= 0) { b.redIReduce() }

      var b32a = a.toBuffer()
      bnUtil.testBN(a.redAdd(b), BigNum.fromBuffer(b32a).add(BigNum.fromBuffer(b.toBuffer())).mod(bnUtil.P))
      expect(a.toBuffer().toString('hex')).to.equal(b32a.toString('hex'))
    })
  })

  describe('redIAdd', function () {
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

  describe('redIAdd7', function () {
    it('(p - 8) + 7 -> p - 1', function () {
      var bn = BN.fromBuffer(bnUtil.P.sub(8).toBuffer())
      bnUtil.testBN(bn.redIAdd7(), bnUtil.P.sub(1))
      bnUtil.testBN(bn, bnUtil.P.sub(1))
    })

    it('(p - 7) + 7 -> 0', function () {
      var bn = BN.fromBuffer(bnUtil.P.sub(7).toBuffer())
      bnUtil.testBN(bn.redIAdd7(), BigNum(0))
      bnUtil.testBN(bn, BigNum(0))
    })

    it('(p - 1) + 7 -> 6', function () {
      var bn = BN.fromBuffer(bnUtil.P.sub(1).toBuffer())
      bnUtil.testBN(bn.redIAdd7(), BigNum(6))
      bnUtil.testBN(bn, BigNum(6))
    })
  })

  describe('redSub', function () {
    it('source was not affected', function () {
      var a = BN.fromBuffer(util.getMessage())
      if (a.ucmp(BN.p) >= 0) { a.redIReduce() }
      var b = BN.fromBuffer(util.getTweak())
      if (b.ucmp(BN.p) >= 0) { b.redIReduce() }
      if (a.ucmp(b) === -1) {
        var t = a
        a = b
        b = t
      }

      var b32a = a.toBuffer()
      bnUtil.testBN(a.redSub(b), BigNum.fromBuffer(b32a).sub(BigNum.fromBuffer(b.toBuffer())).mod(bnUtil.P))
      expect(a.toBuffer().toString('hex')).to.equal(b32a.toString('hex'))
    })
  })

  describe('redISub', function () {
    it('0 - 1 -> p - 1', function () {
      var a = BN.fromNumber(0)
      var b = BN.fromNumber(1)
      bnUtil.testBN(a.redISub(b), bnUtil.P.sub(1))
    })

    it('(p - 2) - (p - 1) -> p - 1', function () {
      var a = BN.fromBuffer(bnUtil.fillZeros(bnUtil.P.sub(2).toBuffer()))
      var b = BN.fromBuffer(bnUtil.fillZeros(bnUtil.P.sub(1).toBuffer()))
      bnUtil.testBN(a.redISub(b), bnUtil.P.sub(1))
    })
  })

  describe('redMul', function () {
    util.repeatIt('random tests', util.env.repeat, function () {
      var a = BN.fromBuffer(util.getMessage())
      if (a.ucmp(BN.p) >= 0) { a.redIReduce() }
      var b = BN.fromBuffer(util.getTweak())
      if (b.ucmp(BN.p) >= 0) { b.redIReduce() }

      var bnA = BigNum.fromBuffer(a.toBuffer())
      var bnB = BigNum.fromBuffer(b.toBuffer())
      bnUtil.testBN(a.redMul(b), bnA.mul(bnB).mod(bnUtil.P))
    })
  })

  describe('redSqr', function () {
    util.repeatIt('random tests', util.env.repeat, function () {
      var bn = BN.fromBuffer(util.getMessage())
      if (bn.ucmp(BN.p) >= 0) { bn.redIReduce() }

      bnUtil.testBN(bn.redSqr(), BigNum.fromBuffer(bn.toBuffer()).pow(2).mod(bnUtil.P))
    })
  })

  describe('redSqrt', function () {
    it('return zero for zero', function () {
      bnUtil.testBN(BN.fromNumber(0).redSqrt(), BigNum(0))
    })

    it('return null for quadratic nonresidue', function () {
      var b32 = new Buffer('16e5f9d306371e9b876f04025fb8c8ed10f8b8864119a149803357e77bcdd3b1', 'hex')
      expect(BN.fromBuffer(b32).redSqrt()).to.be.null
    })

    util.repeatIt('random tests', util.env.repeat, function () {
      var bn = BN.fromBuffer(util.getMessage())
      if (bn.ucmp(BN.p) >= 0) { bn.redIReduce() }

      var result = bn.redSqrt()
      if (result !== null) {
        bnUtil.testBN(bn, BigNum.fromBuffer(result.toBuffer()).pow(2).mod(bnUtil.P))
      }
    })
  })

  describe('redInvm', function () {
    util.repeatIt('random tests', util.env.repeat, function () {
      var b32 = util.getMessage()
      var a = BN.fromBuffer(b32)
      if (a.ucmp(BN.p) >= 0) { a.redIReduce() }

      bnUtil.testBN(a.redInvm(), BigNum.fromBuffer(a.toBuffer()).invertm(bnUtil.P))
    })
  })

  describe('getNAF', function () {
    util.repeatIt('random tests', util.env.repeat, function () {
      var b32 = util.getMessage()
      var w = b32[0] % 10 + 1 // [1,10]

      var naf = BN.fromBuffer(b32).getNAF(w)
      var power = BigNum(1)
      var bignum = BigNum(0)
      for (var i = 0; i < naf.length; ++i) {
        bignum = bignum.add(power.mul(naf[i]))
        power = power.mul(2)
      }

      expect(bnUtil.fillZeros(bignum.toBuffer()).toString('hex')).to.equal(b32.toString('hex'))
    })
  })
})
