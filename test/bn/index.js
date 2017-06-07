'use strict'
var Buffer = require('safe-buffer').Buffer
var test = require('tape')
var BigNum = require('bignum')

var BN = require('../../lib/js/bn')
var util = require('../util')
var bnUtil = require('./util')

test('BN', function (t) {
  util.setSeed(util.env.seed)

  t.test('fromNumber', function (t) {
    t.test('0', function (t) {
      var bn = BN.fromNumber(0)
      bnUtil.testBN(t, bn, BigNum(0))
      t.end()
    })

    t.test('2**26-1', function (t) {
      var bn = BN.fromNumber(0x03ffffff)
      bnUtil.testBN(t, bn, BigNum(0x03ffffff))
      t.end()
    })

    t.test('2**26 should equal 0', function (t) {
      var bn = BN.fromNumber(0x04000000)
      bnUtil.testBN(t, bn, BigNum(0))
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var b32 = util.getMessage()
      var num = ((b32[0] << 24) + (b32[1] << 16) + (b32[2] << 8) + b32[3]) & 0x03ffffff
      var bn = BN.fromNumber(num)
      bnUtil.testBN(t, bn, BigNum(num))
      t.end()
    })

    t.end()
  })

  t.test('fromBuffer/toBuffer', function (t) {
    for (var i = 0; i < 10; ++i) {
      t.test('all bits eq 1 in #' + i + ' word', function (t) {
        var b32 = bnUtil.fillZeros(BigNum.pow(2, 26).sub(1).shiftLeft(26 * i).toBuffer())
        var bn = BN.fromBuffer(b32)
        bnUtil.testBN(t, bn, BigNum.fromBuffer(b32))
        t.same(bn.toBuffer(), b32)
        t.end()
      })
    }

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var b32 = util.getMessage()
      var bn = BN.fromBuffer(b32)
      bnUtil.testBN(t, bn, BigNum.fromBuffer(b32))
      t.same(bn.toBuffer(), b32)
      t.end()
    })

    t.end()
  })

  t.skip('clone', function (t) {
    t.end()
  })

  t.test('strip', function (t) {
    t.test('[0] -> [0]', function (t) {
      var bn = new BN()
      bn.words = [0]
      bn.length = 1
      bnUtil.testBN(t, bn.strip(), BigNum(0))
      t.end()
    })

    t.test('[1] -> [1]', function (t) {
      var bn = new BN()
      bn.words = [1]
      bn.length = 1
      bnUtil.testBN(t, bn.strip(), BigNum(1))
      t.end()
    })

    t.test('[0, 0] -> [0]', function (t) {
      var bn = new BN()
      bn.words = [0, 0]
      bn.length = 2
      bnUtil.testBN(t, bn.strip(), BigNum(0))
      t.end()
    })

    t.test('[1, 0] -> [1]', function (t) {
      var bn = new BN()
      bn.words = [1, 0]
      bn.length = 2
      bnUtil.testBN(t, bn.strip(), BigNum(1))
      t.end()
    })

    t.end()
  })

  t.test('normSign', function (t) {
    t.test('1 -> 1', function (t) {
      var bn = BN.fromNumber(1)
      bnUtil.testBN(t, bn.normSign(), BigNum(1))
      t.end()
    })

    t.test('-1 -> -1', function (t) {
      var bn = BN.fromNumber(1)
      bn.negative = 1
      bnUtil.testBN(t, bn.normSign(), BigNum(-1))
      t.end()
    })

    t.test('0 -> 0', function (t) {
      var bn = BN.fromNumber(0)
      bnUtil.testBN(t, bn.normSign(), BigNum(0))
      t.end()
    })

    t.test('-0 -> 0', function (t) {
      var bn = BN.fromNumber(0)
      bn.negative = 1
      bnUtil.testBN(t, bn.normSign(), BigNum(0))
      t.end()
    })

    t.test('0x04000000 -> 0x04000000', function (t) {
      var b32 = bnUtil.fillZeros(Buffer.from([0xff, 0xff, 0xff, 0xff]))
      var bn = BN.fromBuffer(b32)
      bnUtil.testBN(t, bn.normSign(), BigNum.fromBuffer(b32))
      t.end()
    })

    t.test('-0x04000000 -> -0x04000000', function (t) {
      var b32 = bnUtil.fillZeros(Buffer.from([0xff, 0xff, 0xff, 0xff]))
      var bn = BN.fromBuffer(b32)
      bn.negative = 1
      bnUtil.testBN(t, bn.normSign(), BigNum.fromBuffer(b32).neg())
      t.end()
    })

    t.end()
  })

  t.test('isEven', function (t) {
    t.test('[0] -> true', function (t) {
      t.true(BN.fromNumber(0).isEven())
      t.end()
    })

    t.test('[1] -> false', function (t) {
      t.false(BN.fromNumber(1).isEven())
      t.end()
    })

    t.end()
  })

  t.test('isOdd', function (t) {
    t.test('[0] -> false', function (t) {
      t.false(BN.fromNumber(0).isOdd())
      t.end()
    })

    t.test('[1] -> true', function (t) {
      t.true(BN.fromNumber(1).isOdd())
      t.end()
    })

    t.end()
  })

  t.test('isZero', function (t) {
    t.test('[0] -> true', function (t) {
      t.true(BN.fromNumber(0).isZero())
      t.end()
    })

    t.test('[1] -> false', function (t) {
      t.false(BN.fromNumber(1).isZero())
      t.end()
    })

    t.end()
  })

  t.test('ucmp', function (t) {
    t.test('a.length > b.length', function (t) {
      var a = new BN()
      a.length = 2
      var b = new BN()
      b.length = 1
      t.same(a.ucmp(b), 1)
      t.end()
    })

    t.test('a.length < b.length', function (t) {
      var a = new BN()
      a.length = 1
      var b = new BN()
      b.length = 2
      t.same(a.ucmp(b), -1)
      t.end()
    })

    t.test('[2] > [1]', function (t) {
      var a = BN.fromNumber(2)
      var b = BN.fromNumber(1)
      t.same(a.ucmp(b), 1)
      t.end()
    })

    t.test('[1] < [2]', function (t) {
      var a = BN.fromNumber(1)
      var b = BN.fromNumber(2)
      t.same(a.ucmp(b), -1)
      t.end()
    })

    t.test('[1] = [1]', function (t) {
      var a = BN.fromNumber(1)
      var b = BN.fromNumber(1)
      t.same(a.ucmp(b), 0)
      t.end()
    })

    t.test('-2 > 1', function (t) {
      var a = BN.fromNumber(2)
      a.negative = 1
      var b = BN.fromNumber(1)
      t.same(a.ucmp(b), 1)
      t.end()
    })

    t.test('1 < -2', function (t) {
      var a = BN.fromNumber(1)
      var b = BN.fromNumber(2)
      b.negative = 1
      t.same(a.ucmp(b), -1)
      t.end()
    })

    t.test('-1 = -1', function (t) {
      var a = BN.fromNumber(1)
      a.negative = 1
      var b = BN.fromNumber(1)
      b.negative = 1
      t.same(a.ucmp(b), 0)
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var b32a = util.getMessage()
      var b32b = util.getTweak()
      var a = BN.fromBuffer(b32a)
      var b = BN.fromBuffer(b32b)
      t.same(a.ucmp(b), BigNum.fromBuffer(b32a).cmp(BigNum.fromBuffer(b32b)))
      t.end()
    })

    t.end()
  })

  t.test('gtOne', function (t) {
    t.test('0', function (t) {
      var bn = BN.fromNumber(0)
      t.false(bn.gtOne())
      t.end()
    })

    t.test('1', function (t) {
      var bn = BN.fromNumber(1)
      t.false(bn.gtOne())
      t.end()
    })

    t.test('2', function (t) {
      var bn = BN.fromNumber(2)
      t.true(bn.gtOne())
      t.end()
    })

    t.test('length > 1', function (t) {
      var bn = new BN()
      bn.length = 2
      t.true(bn.gtOne())
      t.end()
    })
  })

  t.test('isOverflow', function (t) {
    t.test('0', function (t) {
      var bn = BN.fromBuffer(bnUtil.fillZeros(BigNum(0).toBuffer()))
      t.false(bn.isOverflow())
      t.end()
    })

    t.test('n - 1', function (t) {
      var bn = BN.fromBuffer(bnUtil.fillZeros(bnUtil.N.sub(1).toBuffer()))
      t.false(bn.isOverflow())
      t.end()
    })

    t.test('n', function (t) {
      var bn = BN.fromBuffer(bnUtil.fillZeros(bnUtil.N.toBuffer()))
      t.true(bn.isOverflow())
      t.end()
    })

    t.test('n + 1', function (t) {
      var bn = BN.fromBuffer(bnUtil.fillZeros(bnUtil.N.add(1).toBuffer()))
      t.true(bn.isOverflow())
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var b32 = util.getMessage()
      var bn = BN.fromBuffer(b32)
      t.same(bn.isOverflow(), bnUtil.N.cmp(BigNum.fromBuffer(b32)) <= 0)
      t.end()
    })

    t.end()
  })

  t.test('isHigh', function (t) {
    t.test('0', function (t) {
      var bn = BN.fromBuffer(bnUtil.fillZeros(BigNum(0).toBuffer()))
      t.false(bn.isHigh())
      t.end()
    })

    t.test('nh - 1', function (t) {
      var bn = BN.fromBuffer(bnUtil.fillZeros(bnUtil.NH.sub(1).toBuffer()))
      t.false(bn.isHigh())
      t.end()
    })

    t.test('nh', function (t) {
      var bn = BN.fromBuffer(bnUtil.fillZeros(bnUtil.NH.toBuffer()))
      t.false(bn.isHigh())
      t.end()
    })

    t.test('nh + 1', function (t) {
      var bn = BN.fromBuffer(bnUtil.fillZeros(bnUtil.NH.add(1).toBuffer()))
      t.true(bn.isHigh())
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var b32 = util.getMessage()
      var bn = BN.fromBuffer(b32)
      t.same(bn.isHigh(), bnUtil.NH.cmp(BigNum.fromBuffer(b32)) <= 0)
      t.end()
    })

    t.end()
  })

  t.test('bitLengthGT256', function (t) {
    t.test('length eq 9', function (t) {
      var bn = new BN()
      bn.length = 9
      t.false(bn.bitLengthGT256())
      t.end()
    })

    t.test('length eq 10 and last word is 0x003fffff', function (t) {
      var bn = new BN()
      bn.words = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0x003fffff]
      bn.length = 10
      t.false(bn.bitLengthGT256())
      t.end()
    })

    t.test('length eq 10 and last word is 0x00400000', function (t) {
      var bn = new BN()
      bn.words = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00400000]
      bn.length = 10
      t.true(bn.bitLengthGT256())
      t.end()
    })

    t.test('length eq 11', function (t) {
      var bn = new BN()
      bn.length = 11
      t.true(bn.bitLengthGT256())
      t.end()
    })

    t.end()
  })

  t.test('iuaddn', function (t) {
    t.test('1 + 1', function (t) {
      var bn = BN.fromNumber(1)
      bnUtil.testBN(t, bn.iuaddn(1), BigNum(2))
      t.end()
    })

    t.test('0x03ffffff + 1', function (t) {
      var bn = BN.fromNumber(0x03ffffff)
      bnUtil.testBN(t, bn.iuaddn(1), BigNum(0x04000000))
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var b32 = util.getMessage()
      b32[0] = 0
      var bn = BN.fromBuffer(b32)
      var x = ((b32[1] << 24) + (b32[2] << 16) + (b32[3] << 8) + b32[4]) & 0x03ffffff
      bnUtil.testBN(t, bn.iuaddn(x), BigNum.fromBuffer(b32).add(x))
      t.end()
    })

    t.end()
  })

  t.test('iadd', function (t) {
    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var b32A = util.getMessage()
      var b32B = util.getTweak()

      var a = BN.fromBuffer(b32A)
      var ac = a.clone()
      var b = BN.fromBuffer(b32B)

      // a + b
      bnUtil.testBN(t, a.iadd(b), BigNum.fromBuffer(b32A).add(BigNum.fromBuffer(b32B)))
      a.words = ac.clone().words
      a.length = ac.length
      a.negative = 1
      // (-a) + b
      bnUtil.testBN(t, a.iadd(b), BigNum.fromBuffer(b32A).neg().add(BigNum.fromBuffer(b32B)))
      a.words = ac.clone().words
      a.length = ac.length
      a.negative = 1
      b.negative = 1
      // (-a) + (-b)
      bnUtil.testBN(t, a.iadd(b), BigNum.fromBuffer(b32A).neg().add(BigNum.fromBuffer(b32B).neg()))
      a.words = ac.clone().words
      a.length = ac.length
      a.negative = 0
      // a + (-b)
      bnUtil.testBN(t, a.iadd(b), BigNum.fromBuffer(b32A).add(BigNum.fromBuffer(b32B).neg()))

      t.end()
    })

    t.end()
  })

  t.test('add', function (t) {
    t.test('source was not affected', function (t) {
      var b32a = util.getMessage()
      var b32b = util.getTweak()

      var a = BN.fromBuffer(b32a)
      var b = BN.fromBuffer(b32b)

      bnUtil.testBN(t, a.add(b), BigNum.fromBuffer(b32a).add(BigNum.fromBuffer(b32b)))
      t.same(a.toBuffer(), b32a)
      t.end()
    })

    t.end()
  })

  t.test('isub', function (t) {
    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var b32A = util.getMessage()
      var b32B = util.getTweak()

      var a = BN.fromBuffer(b32A)
      var ac = a.clone()
      var b = BN.fromBuffer(b32B)

      // a - b
      bnUtil.testBN(t, a.isub(b), BigNum.fromBuffer(b32A).sub(BigNum.fromBuffer(b32B)))
      a.words = ac.clone().words
      a.length = ac.length
      a.negative = 1
      // (-a) + b
      bnUtil.testBN(t, a.isub(b), BigNum.fromBuffer(b32A).neg().sub(BigNum.fromBuffer(b32B)))
      a.words = ac.clone().words
      b.negative = 1
      a.length = ac.length
      // (-a) + (-b)
      bnUtil.testBN(t, a.isub(b), BigNum.fromBuffer(b32A).neg().sub(BigNum.fromBuffer(b32B).neg()))
      a.words = ac.clone().words
      a.negative = 0
      // a + (-b)
      a.length = ac.length
      bnUtil.testBN(t, a.isub(b), BigNum.fromBuffer(b32A).sub(BigNum.fromBuffer(b32B).neg()))
      t.end()
    })

    t.end()
  })

  t.test('sub', function (t) {
    t.test('source was not affected', function (t) {
      var b32a = util.getMessage()
      var b32b = util.getTweak()

      var a = BN.fromBuffer(b32a)
      var b = BN.fromBuffer(b32b)

      bnUtil.testBN(t, a.sub(b), BigNum.fromBuffer(b32a).sub(BigNum.fromBuffer(b32b)))
      t.same(a.toBuffer(), b32a)
      t.end()
    })

    t.end()
  })

  t.test('umul', function (t) {
    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var b32A = util.getMessage()
      var b32B = util.getTweak()
      var bnR = BigNum.fromBuffer(b32A).mul(BigNum.fromBuffer(b32B))

      var a = BN.fromBuffer(b32A)
      var b = BN.fromBuffer(b32B)
      var r = a.umul(b)

      bnUtil.testBN(t, r, bnR)
      t.end()
    })

    t.end()
  })

  t.test('umul', function (t) {
    var out = BN.fromNumber(0)

    t.test('umulnTo', function (t) {
      t.test('[0x03ffffff] * 0', function (t) {
        BN.umulnTo(BN.fromNumber(0x03ffffff), 0, out)
        bnUtil.testBN(t, out, BigNum(0))
        t.end()
      })

      t.test('[0x03ffffff] * 0x03ffffff', function (t) {
        BN.umulnTo(BN.fromNumber(0x03ffffff), 0x03ffffff, out)
        bnUtil.testBN(t, out, BigNum(0x03ffffff).mul(0x03ffffff))
        t.end()
      })

      t.test('[0x03ffffff, 0x03ffffff] * 0x03ffffff', function (t) {
        var bn = new BN()
        bn.words = [0x03ffffff, 0x03ffffff]
        bn.length = 2
        BN.umulnTo(bn, 0x03ffffff, out)
        bnUtil.testBN(t, out, BigNum.fromBuffer(bn.toBuffer()).mul(0x03ffffff))
        t.end()
      })

      t.end()
    })

    t.test('umulTo', function (t) {
      util.repeat(t, 'random tests', util.env.repeat, function (t) {
        var b32a = util.getMessage()
        var b32b = util.getTweak()

        var a = BN.fromBuffer(b32a)
        a.length = b32a[0] % 8 + 2 // in [1,9]
        var b = BN.fromBuffer(b32b)
        b.length = b32b[0] % 8 + 2 // in [1,9]

        BN.umulTo(a, b, out)
        bnUtil.testBN(t, out, BigNum.fromBuffer(a.toBuffer()).mul(BigNum.fromBuffer(b.toBuffer())))
        t.end()
      })

      t.end()
    })

    t.test('10x * 10x', function (t) {
      var min = BigNum(1).shiftLeft(235).sub(1)
      var bnMin = BN.fromBuffer(bnUtil.fillZeros(min.toBuffer()))
      var max = BigNum(1).shiftLeft(256).sub(1)
      var bnMax = BN.fromBuffer(max.toBuffer())

      function test (descripion, fn) {
        t.test(descripion, function (t) {
          t.test('min * min', function (t) {
            fn(bnMin, bnMin, out)
            bnUtil.testBN(t, out, min.mul(min))
            t.end()
          })

          t.test('min * max', function (t) {
            fn(bnMin, bnMax, out)
            bnUtil.testBN(t, out, min.mul(max))
            t.end()
          })

          t.test('max * min', function (t) {
            fn(bnMax, bnMin, out)
            bnUtil.testBN(t, out, max.mul(min))
            t.end()
          })

          t.test('max * max', function (t) {
            fn(bnMax, bnMax, out)
            bnUtil.testBN(t, out, max.mul(max))
            t.end()
          })

          util.repeat(t, 'random tests', util.env.repeat, function (t) {
            var a
            var b
            while (!a || !b || a.length !== 10 || b.length !== 10) {
              a = BN.fromBuffer(util.getMessage())
              b = BN.fromBuffer(util.getTweak())
            }

            BN.umulTo(a, b, out)
            bnUtil.testBN(t, out, BigNum.fromBuffer(a.toBuffer()).mul(BigNum.fromBuffer(b.toBuffer())))
            t.end()
          })

          t.end()
        })
      }

      test('umulTo', BN.umulTo)
      if (Math.imul !== undefined) test('optimized', require('../../lib/js/bn/optimized').umulTo10x10)

      t.end()
    })

    t.end()
  })

  t.test('isplit', function (t) {
    t.test('from 0 to 512 bits', function (t) {
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
        bnUtil.testBN(t, tmp, bignum.and(bignum256))
        bnUtil.testBN(t, bn, bignum.shiftRight(256))
      }

      t.end()
    })

    t.end()
  })

  t.test('fireduce', function (t) {
    t.test('n - 1 -> n - 1', function (t) {
      var bn = BN.fromBuffer(bnUtil.N.sub(1).toBuffer())
      bnUtil.testBN(t, bn.fireduce(), bnUtil.N.sub(1))
      t.end()
    })

    t.test('n -> 0', function (t) {
      var bn = BN.fromBuffer(bnUtil.N.toBuffer())
      bnUtil.testBN(t, bn.fireduce(), BigNum(0))
      t.end()
    })

    t.test('2*n - 1 -> n - 1', function (t) {
      var bn = BN.umulnTo(BN.fromBuffer(bnUtil.N.toBuffer()), 2, BN.fromNumber(0)).isub(BN.fromNumber(1))
      bnUtil.testBN(t, bn.fireduce(), bnUtil.N.sub(1))
      t.end()
    })

    t.test('2*n -> n', function (t) {
      var bn = BN.umulnTo(BN.fromBuffer(bnUtil.N.toBuffer()), 2, BN.fromNumber(0))
      bnUtil.testBN(t, bn.fireduce(), bnUtil.N)
      t.end()
    })
  })

  t.test('ureduce', function (t) {
    t.test('n - 1 -> n - 1', function (t) {
      var bn = BN.fromBuffer(bnUtil.N.sub(1).toBuffer())
      bnUtil.testBN(t, bn.ureduce(), bnUtil.N.sub(1))
      t.end()
    })

    t.test('n -> 0', function (t) {
      var bn = BN.fromBuffer(bnUtil.N.toBuffer())
      bnUtil.testBN(t, bn.ureduce(), BigNum(0))
      t.end()
    })

    t.test('n*n - 1 -> n - 1', function (t) {
      var bn = BN.fromBuffer(bnUtil.N.toBuffer())
      bnUtil.testBN(t, bn.umul(bn).sub(BN.fromNumber(1)).ureduce(), bnUtil.N.sub(1))
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var b32a = util.getMessage()
      var b32b = util.getTweak()

      var a = BN.fromBuffer(b32a)
      var b = BN.fromBuffer(b32b)

      bnUtil.testBN(t, a.umul(b).ureduce(), BigNum.fromBuffer(b32a).mul(BigNum.fromBuffer(b32b)).mod(bnUtil.N))
      t.end()
    })

    t.end()
  })

  t.test('ishrn', function (t) {
    t.test('51 bits eq 1, shift from 0 to 26', function (t) {
      var b32 = bnUtil.fillZeros(Buffer.from('07ffffffffffff', 'hex'))
      for (var i = 0; i < 26; ++i) {
        bnUtil.testBN(t, BN.fromBuffer(b32).ishrn(i), BigNum.fromBuffer(b32).shiftRight(i))
      }
      t.end()
    })

    t.test('256 bits eq 1, shift from 0 to 26', function (t) {
      var b32 = Buffer.alloc(32)
      b32.fill(0xff)
      for (var i = 0; i < 26; ++i) {
        bnUtil.testBN(t, BN.fromBuffer(b32).ishrn(i), BigNum.fromBuffer(b32).shiftRight(i))
      }
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var b32 = util.getMessage()
      var shift = b32[0] % 26
      bnUtil.testBN(t, BN.fromBuffer(b32).ishrn(shift), BigNum.fromBuffer(b32).shiftRight(shift))
      t.end()
    })

    t.end()
  })

  t.test('uinvm', function (t) {
    t.test('0', function (t) {
      bnUtil.testBN(t, BN.fromNumber(0).uinvm(), BigNum(0).invertm(bnUtil.N))
      t.end()
    })

    t.test('n - 1', function (t) {
      var b32 = bnUtil.N.sub(1).toBuffer()
      bnUtil.testBN(t, BN.fromBuffer(b32).uinvm(), BigNum.fromBuffer(b32).invertm(bnUtil.N))
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var b32 = util.getMessage()
      bnUtil.testBN(t, BN.fromBuffer(b32).uinvm(), BigNum.fromBuffer(b32).invertm(bnUtil.N))
      t.end()
    })

    t.end()
  })

  t.test('imulK', function (t) {
    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var b32 = util.getMessage()
      var bn = BN.fromBuffer(b32)
      bnUtil.testBN(t, bn.imulK(), BigNum.fromBuffer(b32).mul(bnUtil.K))
      t.end()
    })

    t.end()
  })

  t.test('redIReduce', function (t) {
    t.test('p - 1 -> p - 1', function (t) {
      var bn = BN.fromBuffer(bnUtil.P.sub(1).toBuffer())
      bnUtil.testBN(t, bn.redIReduce(), bnUtil.P.sub(1))
      t.end()
    })

    t.test('p -> 0', function (t) {
      var bn = BN.fromBuffer(bnUtil.P.toBuffer())
      bnUtil.testBN(t, bn.redIReduce(), BigNum(0))
      t.end()
    })

    t.test('p*p - 1 -> p - 1', function (t) {
      var bn = BN.fromBuffer(bnUtil.P.toBuffer())
      bnUtil.testBN(t, bn.umul(bn).sub(BN.fromNumber(1)).redIReduce(), bnUtil.P.sub(1))
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var a = BN.fromBuffer(util.getMessage())
      if (a.ucmp(BN.p) >= 0) a.redIReduce()
      var b = BN.fromBuffer(util.getTweak())
      if (b.ucmp(BN.p) >= 0) b.redIReduce()

      var abn = BigNum.fromBuffer(a.toBuffer())
      var bbn = BigNum.fromBuffer(b.toBuffer())
      bnUtil.testBN(t, a.umul(b).redIReduce(), abn.mul(bbn).mod(bnUtil.P))
      t.end()
    })

    t.end()
  })

  t.test('redNeg', function (t) {
    t.test('0 -> 0', function (t) {
      var bn = BN.fromBuffer(bnUtil.fillZeros(BigNum(0).toBuffer()))
      bnUtil.testBN(t, bn.redNeg(), BigNum(0))
      t.end()
    })

    t.test('1 -> p - 1', function (t) {
      var bn = BN.fromBuffer(bnUtil.fillZeros(BigNum(1).toBuffer()))
      bnUtil.testBN(t, bn.redNeg(), bnUtil.P.sub(1))
      t.end()
    })

    t.test('p - 1 -> 1', function (t) {
      var bn = BN.fromBuffer(bnUtil.fillZeros(bnUtil.P.sub(1).toBuffer()))
      bnUtil.testBN(t, bn.redNeg(), BigNum(1))
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var bn = BN.fromBuffer(util.getMessage())
      if (bn.ucmp(BN.p) >= 0) bn.redIReduce()

      bnUtil.testBN(t, bn.redNeg(), bnUtil.P.sub(BigNum.fromBuffer(bn.toBuffer())))
      t.end()
    })

    t.end()
  })

  t.test('redAdd', function (t) {
    t.test('source was not affected', function (t) {
      var a = BN.fromBuffer(util.getMessage())
      if (a.ucmp(BN.p) >= 0) a.redIReduce()
      var b = BN.fromBuffer(util.getTweak())
      if (b.ucmp(BN.p) >= 0) b.redIReduce()

      var b32a = a.toBuffer()
      bnUtil.testBN(t, a.redAdd(b), BigNum.fromBuffer(b32a).add(BigNum.fromBuffer(b.toBuffer())).mod(bnUtil.P))
      t.same(a.toBuffer(), b32a)
      t.end()
    })

    t.end()
  })

  t.test('redIAdd', function (t) {
    t.test('(p - 2) + 1 -> p - 1', function (t) {
      var a = BN.fromBuffer(bnUtil.fillZeros(bnUtil.P.sub(2).toBuffer()))
      var b = BN.fromBuffer(bnUtil.fillZeros(BigNum(1).toBuffer()))
      bnUtil.testBN(t, a.redAdd(b), bnUtil.P.sub(1))
      t.end()
    })

    t.test('(p - 1) + 1 -> 0', function (t) {
      var a = BN.fromBuffer(bnUtil.fillZeros(bnUtil.P.sub(1).toBuffer()))
      var b = BN.fromBuffer(bnUtil.fillZeros(BigNum(1).toBuffer()))
      bnUtil.testBN(t, a.redAdd(b), BigNum(0))
      t.end()
    })

    t.test('(p - 1) + 2 -> 1', function (t) {
      var a = BN.fromBuffer(bnUtil.fillZeros(bnUtil.P.sub(1).toBuffer()))
      var b = BN.fromBuffer(bnUtil.fillZeros(BigNum(2).toBuffer()))
      bnUtil.testBN(t, a.redAdd(b), BigNum(1))
      t.end()
    })

    t.test('(p - 1) + (p - 1) -> p - 2', function (t) {
      var a = BN.fromBuffer(bnUtil.fillZeros(bnUtil.P.sub(1).toBuffer()))
      var b = BN.fromBuffer(bnUtil.fillZeros(bnUtil.P.sub(1).toBuffer()))
      bnUtil.testBN(t, a.redAdd(b), bnUtil.P.sub(2))
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var a = BN.fromBuffer(util.getMessage())
      var b = BN.fromBuffer(util.getTweak())
      bnUtil.testBN(t, a.redAdd(b), BigNum.fromBuffer(a.toBuffer()).add(BigNum.fromBuffer(b.toBuffer())).mod(bnUtil.P))
      t.end()
    })

    t.end()
  })

  t.test('redIAdd7', function (t) {
    t.test('(p - 8) + 7 -> p - 1', function (t) {
      var bn = BN.fromBuffer(bnUtil.P.sub(8).toBuffer())
      bnUtil.testBN(t, bn.redIAdd7(), bnUtil.P.sub(1))
      bnUtil.testBN(t, bn, bnUtil.P.sub(1))
      t.end()
    })

    t.test('(p - 7) + 7 -> 0', function (t) {
      var bn = BN.fromBuffer(bnUtil.P.sub(7).toBuffer())
      bnUtil.testBN(t, bn.redIAdd7(), BigNum(0))
      bnUtil.testBN(t, bn, BigNum(0))
      t.end()
    })

    t.test('(p - 1) + 7 -> 6', function (t) {
      var bn = BN.fromBuffer(bnUtil.P.sub(1).toBuffer())
      bnUtil.testBN(t, bn.redIAdd7(), BigNum(6))
      bnUtil.testBN(t, bn, BigNum(6))
      t.end()
    })

    t.end()
  })

  t.test('redSub', function (t) {
    t.test('source was not affected', function (t) {
      var a = BN.fromBuffer(util.getMessage())
      if (a.ucmp(BN.p) >= 0) a.redIReduce()
      var b = BN.fromBuffer(util.getTweak())
      if (b.ucmp(BN.p) >= 0) b.redIReduce()
      if (a.ucmp(b) === -1) {
        var tmp = a
        a = b
        b = tmp
      }

      var b32a = a.toBuffer()
      bnUtil.testBN(t, a.redSub(b), BigNum.fromBuffer(b32a).sub(BigNum.fromBuffer(b.toBuffer())).mod(bnUtil.P))
      t.same(a.toBuffer(), b32a)
      t.end()
    })

    t.end()
  })

  t.test('redISub', function (t) {
    t.test('0 - 1 -> p - 1', function (t) {
      var a = BN.fromNumber(0)
      var b = BN.fromNumber(1)
      bnUtil.testBN(t, a.redISub(b), bnUtil.P.sub(1))
      t.end()
    })

    t.test('(p - 2) - (p - 1) -> p - 1', function (t) {
      var a = BN.fromBuffer(bnUtil.fillZeros(bnUtil.P.sub(2).toBuffer()))
      var b = BN.fromBuffer(bnUtil.fillZeros(bnUtil.P.sub(1).toBuffer()))
      bnUtil.testBN(t, a.redISub(b), bnUtil.P.sub(1))
      t.end()
    })

    t.end()
  })

  t.test('redMul', function (t) {
    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var a = BN.fromBuffer(util.getMessage())
      if (a.ucmp(BN.p) >= 0) a.redIReduce()
      var b = BN.fromBuffer(util.getTweak())
      if (b.ucmp(BN.p) >= 0) b.redIReduce()

      var bnA = BigNum.fromBuffer(a.toBuffer())
      var bnB = BigNum.fromBuffer(b.toBuffer())
      bnUtil.testBN(t, a.redMul(b), bnA.mul(bnB).mod(bnUtil.P))
      t.end()
    })

    t.end()
  })

  t.test('redSqr', function (t) {
    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var bn = BN.fromBuffer(util.getMessage())
      if (bn.ucmp(BN.p) >= 0) bn.redIReduce()

      bnUtil.testBN(t, bn.redSqr(), BigNum.fromBuffer(bn.toBuffer()).pow(2).mod(bnUtil.P))
      t.end()
    })

    t.end()
  })

  t.test('redSqrt', function (t) {
    t.test('return zero for zero', function (t) {
      bnUtil.testBN(t, BN.fromNumber(0).redSqrt(), BigNum(0))
      t.end()
    })

    t.test('return null for quadratic nonresidue', function (t) {
      var b32 = Buffer.from('16e5f9d306371e9b876f04025fb8c8ed10f8b8864119a149803357e77bcdd3b1', 'hex')
      t.same(BN.fromBuffer(b32).redSqrt(), null)
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var bn = BN.fromBuffer(util.getMessage())
      if (bn.ucmp(BN.p) >= 0) bn.redIReduce()

      var result = bn.redSqrt()
      if (result !== null) bnUtil.testBN(t, bn, BigNum.fromBuffer(result.toBuffer()).pow(2).mod(bnUtil.P))

      t.end()
    })

    t.end()
  })

  t.test('redInvm', function (t) {
    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var b32 = util.getMessage()
      var a = BN.fromBuffer(b32)
      if (a.ucmp(BN.p) >= 0) a.redIReduce()

      bnUtil.testBN(t, a.redInvm(), BigNum.fromBuffer(a.toBuffer()).invertm(bnUtil.P))
      t.end()
    })

    t.end()
  })

  t.test('getNAF', function (t) {
    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var b32 = util.getMessage()
      var w = b32[0] % 10 + 1 // [1, 10]

      var naf = BN.fromBuffer(b32).getNAF(w)
      var power = BigNum(1)
      var bignum = BigNum(0)
      for (var i = 0; i < naf.length; ++i) {
        bignum = bignum.add(power.mul(naf[i]))
        power = power.mul(2)
      }

      t.same(bnUtil.fillZeros(bignum.toBuffer()), b32)
      t.end()
    })

    t.end()
  })

  t.end()
})
