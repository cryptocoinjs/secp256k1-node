import test from 'tape'
import BigNum from 'bignum'

import BN from '../../../es/js/bn'
import * as util from '../../util'
import * as bnUtil from './util'

test('BN', (t) => {
  util.setSeed(util.env.SEED)

  t.test('fromNumber', (t) => {
    t.test('0', (t) => {
      const bn = BN.fromNumber(0)
      bnUtil.testBN(t, bn, BigNum(0))
      t.end()
    })

    t.test('2**26-1', (t) => {
      const bn = BN.fromNumber(0x03ffffff)
      bnUtil.testBN(t, bn, BigNum(0x03ffffff))
      t.end()
    })

    t.test('2**26 should equal 0', (t) => {
      const bn = BN.fromNumber(0x04000000)
      bnUtil.testBN(t, bn, BigNum(0))
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const b32 = util.getMessage()
        const num = ((b32[0] << 24) + (b32[1] << 16) + (b32[2] << 8) + b32[3]) & 0x03ffffff
        const bn = BN.fromNumber(num)
        bnUtil.testBN(t, bn, BigNum(num))
        t.end()
      })
    }

    t.end()
  })

  t.test('fromBuffer/toBuffer', (t) => {
    for (let i = 0; i < 10; ++i) {
      t.test(`all bits eq 1 in #${i} word`, (t) => {
        const b32 = bnUtil.fillZeros(BigNum.pow(2, 26).sub(1).shiftLeft(26 * i).toBuffer())
        const bn = BN.fromBuffer(b32)
        bnUtil.testBN(t, bn, BigNum.fromBuffer(b32))
        t.same(bn.toBuffer(), b32)
        t.end()
      })
    }

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const b32 = util.getMessage()
        const bn = BN.fromBuffer(b32)
        bnUtil.testBN(t, bn, BigNum.fromBuffer(b32))
        t.same(bn.toBuffer(), b32)
        t.end()
      })
    }

    t.end()
  })

  t.skip('clone', (t) => {
    t.end()
  })

  t.test('strip', (t) => {
    t.test('[0] -> [0]', (t) => {
      const bn = new BN()
      bn.words = [0]
      bn.length = 1
      bnUtil.testBN(t, bn.strip(), BigNum(0))
      t.end()
    })

    t.test('[1] -> [1]', (t) => {
      const bn = new BN()
      bn.words = [1]
      bn.length = 1
      bnUtil.testBN(t, bn.strip(), BigNum(1))
      t.end()
    })

    t.test('[0, 0] -> [0]', (t) => {
      const bn = new BN()
      bn.words = [0, 0]
      bn.length = 2
      bnUtil.testBN(t, bn.strip(), BigNum(0))
      t.end()
    })

    t.test('[1, 0] -> [1]', (t) => {
      const bn = new BN()
      bn.words = [1, 0]
      bn.length = 2
      bnUtil.testBN(t, bn.strip(), BigNum(1))
      t.end()
    })

    t.end()
  })

  t.test('normSign', (t) => {
    t.test('1 -> 1', (t) => {
      const bn = BN.fromNumber(1)
      bnUtil.testBN(t, bn.normSign(), BigNum(1))
      t.end()
    })

    t.test('-1 -> -1', (t) => {
      const bn = BN.fromNumber(1)
      bn.negative = 1
      bnUtil.testBN(t, bn.normSign(), BigNum(-1))
      t.end()
    })

    t.test('0 -> 0', (t) => {
      const bn = BN.fromNumber(0)
      bnUtil.testBN(t, bn.normSign(), BigNum(0))
      t.end()
    })

    t.test('-0 -> 0', (t) => {
      const bn = BN.fromNumber(0)
      bn.negative = 1
      bnUtil.testBN(t, bn.normSign(), BigNum(0))
      t.end()
    })

    t.test('0x04000000 -> 0x04000000', (t) => {
      const b32 = bnUtil.fillZeros(Buffer.from([0xff, 0xff, 0xff, 0xff]))
      const bn = BN.fromBuffer(b32)
      bnUtil.testBN(t, bn.normSign(), BigNum.fromBuffer(b32))
      t.end()
    })

    t.test('-0x04000000 -> -0x04000000', (t) => {
      const b32 = bnUtil.fillZeros(Buffer.from([0xff, 0xff, 0xff, 0xff]))
      const bn = BN.fromBuffer(b32)
      bn.negative = 1
      bnUtil.testBN(t, bn.normSign(), BigNum.fromBuffer(b32).neg())
      t.end()
    })

    t.end()
  })

  t.test('isEven', (t) => {
    t.test('[0] -> true', (t) => {
      t.true(BN.fromNumber(0).isEven())
      t.end()
    })

    t.test('[1] -> false', (t) => {
      t.false(BN.fromNumber(1).isEven())
      t.end()
    })

    t.end()
  })

  t.test('isOdd', (t) => {
    t.test('[0] -> false', (t) => {
      t.false(BN.fromNumber(0).isOdd())
      t.end()
    })

    t.test('[1] -> true', (t) => {
      t.true(BN.fromNumber(1).isOdd())
      t.end()
    })

    t.end()
  })

  t.test('isZero', (t) => {
    t.test('[0] -> true', (t) => {
      t.true(BN.fromNumber(0).isZero())
      t.end()
    })

    t.test('[1] -> false', (t) => {
      t.false(BN.fromNumber(1).isZero())
      t.end()
    })

    t.end()
  })

  t.test('ucmp', (t) => {
    t.test('a.length > b.length', (t) => {
      const a = new BN()
      a.length = 2
      const b = new BN()
      b.length = 1
      t.same(a.ucmp(b), 1)
      t.end()
    })

    t.test('a.length < b.length', (t) => {
      const a = new BN()
      a.length = 1
      const b = new BN()
      b.length = 2
      t.same(a.ucmp(b), -1)
      t.end()
    })

    t.test('[2] > [1]', (t) => {
      const a = BN.fromNumber(2)
      const b = BN.fromNumber(1)
      t.same(a.ucmp(b), 1)
      t.end()
    })

    t.test('[1] < [2]', (t) => {
      const a = BN.fromNumber(1)
      const b = BN.fromNumber(2)
      t.same(a.ucmp(b), -1)
      t.end()
    })

    t.test('[1] = [1]', (t) => {
      const a = BN.fromNumber(1)
      const b = BN.fromNumber(1)
      t.same(a.ucmp(b), 0)
      t.end()
    })

    t.test('-2 > 1', (t) => {
      const a = BN.fromNumber(2)
      a.negative = 1
      const b = BN.fromNumber(1)
      t.same(a.ucmp(b), 1)
      t.end()
    })

    t.test('1 < -2', (t) => {
      const a = BN.fromNumber(1)
      const b = BN.fromNumber(2)
      b.negative = 1
      t.same(a.ucmp(b), -1)
      t.end()
    })

    t.test('-1 = -1', (t) => {
      const a = BN.fromNumber(1)
      a.negative = 1
      const b = BN.fromNumber(1)
      b.negative = 1
      t.same(a.ucmp(b), 0)
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const b32a = util.getMessage()
        const b32b = util.getTweak()
        const a = BN.fromBuffer(b32a)
        const b = BN.fromBuffer(b32b)
        t.same(a.ucmp(b), BigNum.fromBuffer(b32a).cmp(BigNum.fromBuffer(b32b)))
        t.end()
      })
    }

    t.end()
  })

  t.test('gtOne', (t) => {
    t.test('0', (t) => {
      const bn = BN.fromNumber(0)
      t.false(bn.gtOne())
      t.end()
    })

    t.test('1', (t) => {
      const bn = BN.fromNumber(1)
      t.false(bn.gtOne())
      t.end()
    })

    t.test('2', (t) => {
      const bn = BN.fromNumber(2)
      t.true(bn.gtOne())
      t.end()
    })

    t.test('length > 1', (t) => {
      const bn = new BN()
      bn.length = 2
      t.true(bn.gtOne())
      t.end()
    })
  })

  t.test('isOverflow', (t) => {
    t.test('0', (t) => {
      const bn = BN.fromBuffer(bnUtil.fillZeros(BigNum(0).toBuffer()))
      t.false(bn.isOverflow())
      t.end()
    })

    t.test('n - 1', (t) => {
      const bn = BN.fromBuffer(bnUtil.fillZeros(bnUtil.N.sub(1).toBuffer()))
      t.false(bn.isOverflow())
      t.end()
    })

    t.test('n', (t) => {
      const bn = BN.fromBuffer(bnUtil.fillZeros(bnUtil.N.toBuffer()))
      t.true(bn.isOverflow())
      t.end()
    })

    t.test('n + 1', (t) => {
      const bn = BN.fromBuffer(bnUtil.fillZeros(bnUtil.N.add(1).toBuffer()))
      t.true(bn.isOverflow())
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const b32 = util.getMessage()
        const bn = BN.fromBuffer(b32)
        t.same(bn.isOverflow(), bnUtil.N.cmp(BigNum.fromBuffer(b32)) <= 0)
        t.end()
      })
    }

    t.end()
  })

  t.test('isHigh', (t) => {
    t.test('0', (t) => {
      const bn = BN.fromBuffer(bnUtil.fillZeros(BigNum(0).toBuffer()))
      t.false(bn.isHigh())
      t.end()
    })

    t.test('nh - 1', (t) => {
      const bn = BN.fromBuffer(bnUtil.fillZeros(bnUtil.NH.sub(1).toBuffer()))
      t.false(bn.isHigh())
      t.end()
    })

    t.test('nh', (t) => {
      const bn = BN.fromBuffer(bnUtil.fillZeros(bnUtil.NH.toBuffer()))
      t.false(bn.isHigh())
      t.end()
    })

    t.test('nh + 1', (t) => {
      const bn = BN.fromBuffer(bnUtil.fillZeros(bnUtil.NH.add(1).toBuffer()))
      t.true(bn.isHigh())
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const b32 = util.getMessage()
        const bn = BN.fromBuffer(b32)
        t.same(bn.isHigh(), bnUtil.NH.cmp(BigNum.fromBuffer(b32)) <= 0)
        t.end()
      })
    }

    t.end()
  })

  t.test('bitLengthGT256', (t) => {
    t.test('length eq 9', (t) => {
      const bn = new BN()
      bn.length = 9
      t.false(bn.bitLengthGT256())
      t.end()
    })

    t.test('length eq 10 and last word is 0x003fffff', (t) => {
      const bn = new BN()
      bn.words = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0x003fffff]
      bn.length = 10
      t.false(bn.bitLengthGT256())
      t.end()
    })

    t.test('length eq 10 and last word is 0x00400000', (t) => {
      const bn = new BN()
      bn.words = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00400000]
      bn.length = 10
      t.true(bn.bitLengthGT256())
      t.end()
    })

    t.test('length eq 11', (t) => {
      const bn = new BN()
      bn.length = 11
      t.true(bn.bitLengthGT256())
      t.end()
    })

    t.end()
  })

  t.test('iuaddn', (t) => {
    t.test('1 + 1', (t) => {
      const bn = BN.fromNumber(1)
      bnUtil.testBN(t, bn.iuaddn(1), BigNum(2))
      t.end()
    })

    t.test('0x03ffffff + 1', (t) => {
      const bn = BN.fromNumber(0x03ffffff)
      bnUtil.testBN(t, bn.iuaddn(1), BigNum(0x04000000))
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const b32 = util.getMessage()
        b32[0] = 0
        const bn = BN.fromBuffer(b32)
        const x = ((b32[1] << 24) + (b32[2] << 16) + (b32[3] << 8) + b32[4]) & 0x03ffffff
        bnUtil.testBN(t, bn.iuaddn(x), BigNum.fromBuffer(b32).add(x))
        t.end()
      })
    }

    t.end()
  })

  t.test('iadd', (t) => {
    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const b32A = util.getMessage()
        const b32B = util.getTweak()

        const a = BN.fromBuffer(b32A)
        const ac = a.clone()
        const b = BN.fromBuffer(b32B)

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
    }

    t.end()
  })

  t.test('add', (t) => {
    t.test('source was not affected', (t) => {
      const b32a = util.getMessage()
      const b32b = util.getTweak()

      const a = BN.fromBuffer(b32a)
      const b = BN.fromBuffer(b32b)

      bnUtil.testBN(t, a.add(b), BigNum.fromBuffer(b32a).add(BigNum.fromBuffer(b32b)))
      t.same(a.toBuffer(), b32a)
      t.end()
    })

    t.end()
  })

  t.test('isub', (t) => {
    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const b32A = util.getMessage()
        const b32B = util.getTweak()

        const a = BN.fromBuffer(b32A)
        const ac = a.clone()
        const b = BN.fromBuffer(b32B)

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
    }

    t.end()
  })

  t.test('sub', (t) => {
    t.test('source was not affected', (t) => {
      const b32a = util.getMessage()
      const b32b = util.getTweak()

      const a = BN.fromBuffer(b32a)
      const b = BN.fromBuffer(b32b)

      bnUtil.testBN(t, a.sub(b), BigNum.fromBuffer(b32a).sub(BigNum.fromBuffer(b32b)))
      t.same(a.toBuffer(), b32a)
      t.end()
    })

    t.end()
  })

  t.test('umul', (t) => {
    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const b32A = util.getMessage()
        const b32B = util.getTweak()
        const bnR = BigNum.fromBuffer(b32A).mul(BigNum.fromBuffer(b32B))

        const a = BN.fromBuffer(b32A)
        const b = BN.fromBuffer(b32B)
        const r = a.umul(b)

        bnUtil.testBN(t, r, bnR)
        t.end()
      })
    }

    t.end()
  })

  t.test('umul', (t) => {
    const out = BN.fromNumber(0)

    t.test('umulnTo', (t) => {
      t.test('[0x03ffffff] * 0', (t) => {
        BN.umulnTo(BN.fromNumber(0x03ffffff), 0, out)
        bnUtil.testBN(t, out, BigNum(0))
        t.end()
      })

      t.test('[0x03ffffff] * 0x03ffffff', (t) => {
        BN.umulnTo(BN.fromNumber(0x03ffffff), 0x03ffffff, out)
        bnUtil.testBN(t, out, BigNum(0x03ffffff).mul(0x03ffffff))
        t.end()
      })

      t.test('[0x03ffffff, 0x03ffffff] * 0x03ffffff', (t) => {
        const bn = new BN()
        bn.words = [0x03ffffff, 0x03ffffff]
        bn.length = 2
        BN.umulnTo(bn, 0x03ffffff, out)
        bnUtil.testBN(t, out, BigNum.fromBuffer(bn.toBuffer()).mul(0x03ffffff))
        t.end()
      })

      t.end()
    })

    t.test('umulTo', (t) => {
      if (!util.env.EDGE_ONLY) {
        util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
          const b32a = util.getMessage()
          const b32b = util.getTweak()

          const a = BN.fromBuffer(b32a)
          a.length = b32a[0] % 8 + 2 // in [1,9]
          const b = BN.fromBuffer(b32b)
          b.length = b32b[0] % 8 + 2 // in [1,9]

          BN.umulTo(a, b, out)
          bnUtil.testBN(t, out, BigNum.fromBuffer(a.toBuffer()).mul(BigNum.fromBuffer(b.toBuffer())))
          t.end()
        })
      }

      t.end()
    })

    t.test('10x * 10x', (t) => {
      const min = BigNum(1).shiftLeft(235).sub(1)
      const bnMin = BN.fromBuffer(bnUtil.fillZeros(min.toBuffer()))
      const max = BigNum(1).shiftLeft(256).sub(1)
      const bnMax = BN.fromBuffer(max.toBuffer())

      function test (descripion, fn) {
        t.test(descripion, (t) => {
          t.test('min * min', (t) => {
            fn(bnMin, bnMin, out)
            bnUtil.testBN(t, out, min.mul(min))
            t.end()
          })

          t.test('min * max', (t) => {
            fn(bnMin, bnMax, out)
            bnUtil.testBN(t, out, min.mul(max))
            t.end()
          })

          t.test('max * min', (t) => {
            fn(bnMax, bnMin, out)
            bnUtil.testBN(t, out, max.mul(min))
            t.end()
          })

          t.test('max * max', (t) => {
            fn(bnMax, bnMax, out)
            bnUtil.testBN(t, out, max.mul(max))
            t.end()
          })

          if (!util.env.EDGE_ONLY) {
            util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
              let a
              let b
              while (!a || !b || a.length !== 10 || b.length !== 10) {
                a = BN.fromBuffer(util.getMessage())
                b = BN.fromBuffer(util.getTweak())
              }

              BN.umulTo(a, b, out)
              bnUtil.testBN(t, out, BigNum.fromBuffer(a.toBuffer()).mul(BigNum.fromBuffer(b.toBuffer())))
              t.end()
            })
          }

          t.end()
        })
      }

      test('umulTo', BN.umulTo)
      if (Math.imul !== undefined) test('optimized', require('../../../es/js/bn/optimized').umulTo10x10)

      t.end()
    })

    t.end()
  })

  t.test('isplit', (t) => {
    t.test('from 0 to 512 bits', (t) => {
      const tmp = new BN()
      tmp.words = new Array(10)
      const bignum256 = BigNum(1).shiftLeft(256).sub(1)

      for (let i = 0; i <= 512; ++i) {
        const bignum = BigNum(1).shiftLeft(i).sub(1)
        const bn = BN.fromNumber(0)
        bn.length = Math.max(Math.ceil(bignum.bitLength() / 26), 1)
        for (let j = 0, bign = bignum; j < bn.length; ++j, bign = bign.shiftRight(26)) {
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

  t.test('fireduce', (t) => {
    t.test('n - 1 -> n - 1', (t) => {
      const bn = BN.fromBuffer(bnUtil.N.sub(1).toBuffer())
      bnUtil.testBN(t, bn.fireduce(), bnUtil.N.sub(1))
      t.end()
    })

    t.test('n -> 0', (t) => {
      const bn = BN.fromBuffer(bnUtil.N.toBuffer())
      bnUtil.testBN(t, bn.fireduce(), BigNum(0))
      t.end()
    })

    t.test('2*n - 1 -> n - 1', (t) => {
      const bn = BN.umulnTo(BN.fromBuffer(bnUtil.N.toBuffer()), 2, BN.fromNumber(0)).isub(BN.fromNumber(1))
      bnUtil.testBN(t, bn.fireduce(), bnUtil.N.sub(1))
      t.end()
    })

    t.test('2*n -> n', (t) => {
      const bn = BN.umulnTo(BN.fromBuffer(bnUtil.N.toBuffer()), 2, BN.fromNumber(0))
      bnUtil.testBN(t, bn.fireduce(), bnUtil.N)
      t.end()
    })
  })

  t.test('ureduce', (t) => {
    t.test('n - 1 -> n - 1', (t) => {
      const bn = BN.fromBuffer(bnUtil.N.sub(1).toBuffer())
      bnUtil.testBN(t, bn.ureduce(), bnUtil.N.sub(1))
      t.end()
    })

    t.test('n -> 0', (t) => {
      const bn = BN.fromBuffer(bnUtil.N.toBuffer())
      bnUtil.testBN(t, bn.ureduce(), BigNum(0))
      t.end()
    })

    t.test('n*n - 1 -> n - 1', (t) => {
      const bn = BN.fromBuffer(bnUtil.N.toBuffer())
      bnUtil.testBN(t, bn.umul(bn).sub(BN.fromNumber(1)).ureduce(), bnUtil.N.sub(1))
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const b32a = util.getMessage()
        const b32b = util.getTweak()

        const a = BN.fromBuffer(b32a)
        const b = BN.fromBuffer(b32b)

        bnUtil.testBN(t, a.umul(b).ureduce(), BigNum.fromBuffer(b32a).mul(BigNum.fromBuffer(b32b)).mod(bnUtil.N))
        t.end()
      })
    }

    t.end()
  })

  t.test('ishrn', (t) => {
    t.test('51 bits eq 1, shift from 0 to 26', (t) => {
      const b32 = bnUtil.fillZeros(Buffer.from('07ffffffffffff', 'hex'))
      for (let i = 0; i < 26; ++i) {
        bnUtil.testBN(t, BN.fromBuffer(b32).ishrn(i), BigNum.fromBuffer(b32).shiftRight(i))
      }
      t.end()
    })

    t.test('256 bits eq 1, shift from 0 to 26', (t) => {
      const b32 = Buffer.alloc(32, 0xFF)
      for (let i = 0; i < 26; ++i) {
        bnUtil.testBN(t, BN.fromBuffer(b32).ishrn(i), BigNum.fromBuffer(b32).shiftRight(i))
      }
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const b32 = util.getMessage()
        const shift = b32[0] % 26
        bnUtil.testBN(t, BN.fromBuffer(b32).ishrn(shift), BigNum.fromBuffer(b32).shiftRight(shift))
        t.end()
      })
    }

    t.end()
  })

  t.test('uinvm', (t) => {
    t.test('0', (t) => {
      bnUtil.testBN(t, BN.fromNumber(0).uinvm(), BigNum(0).invertm(bnUtil.N))
      t.end()
    })

    t.test('n - 1', (t) => {
      const b32 = bnUtil.N.sub(1).toBuffer()
      bnUtil.testBN(t, BN.fromBuffer(b32).uinvm(), BigNum.fromBuffer(b32).invertm(bnUtil.N))
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const b32 = util.getMessage()
        bnUtil.testBN(t, BN.fromBuffer(b32).uinvm(), BigNum.fromBuffer(b32).invertm(bnUtil.N))
        t.end()
      })
    }

    t.end()
  })

  t.test('imulK', (t) => {
    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const b32 = util.getMessage()
        const bn = BN.fromBuffer(b32)
        bnUtil.testBN(t, bn.imulK(), BigNum.fromBuffer(b32).mul(bnUtil.K))
        t.end()
      })
    }

    t.end()
  })

  t.test('redIReduce', (t) => {
    t.test('p - 1 -> p - 1', (t) => {
      const bn = BN.fromBuffer(bnUtil.P.sub(1).toBuffer())
      bnUtil.testBN(t, bn.redIReduce(), bnUtil.P.sub(1))
      t.end()
    })

    t.test('p -> 0', (t) => {
      const bn = BN.fromBuffer(bnUtil.P.toBuffer())
      bnUtil.testBN(t, bn.redIReduce(), BigNum(0))
      t.end()
    })

    t.test('p*p - 1 -> p - 1', (t) => {
      const bn = BN.fromBuffer(bnUtil.P.toBuffer())
      bnUtil.testBN(t, bn.umul(bn).sub(BN.fromNumber(1)).redIReduce(), bnUtil.P.sub(1))
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const a = BN.fromBuffer(util.getMessage())
        if (a.ucmp(BN.p) >= 0) a.redIReduce()
        const b = BN.fromBuffer(util.getTweak())
        if (b.ucmp(BN.p) >= 0) b.redIReduce()

        const abn = BigNum.fromBuffer(a.toBuffer())
        const bbn = BigNum.fromBuffer(b.toBuffer())
        bnUtil.testBN(t, a.umul(b).redIReduce(), abn.mul(bbn).mod(bnUtil.P))
        t.end()
      })
    }

    t.end()
  })

  t.test('redNeg', (t) => {
    t.test('0 -> 0', (t) => {
      const bn = BN.fromBuffer(bnUtil.fillZeros(BigNum(0).toBuffer()))
      bnUtil.testBN(t, bn.redNeg(), BigNum(0))
      t.end()
    })

    t.test('1 -> p - 1', (t) => {
      const bn = BN.fromBuffer(bnUtil.fillZeros(BigNum(1).toBuffer()))
      bnUtil.testBN(t, bn.redNeg(), bnUtil.P.sub(1))
      t.end()
    })

    t.test('p - 1 -> 1', (t) => {
      const bn = BN.fromBuffer(bnUtil.fillZeros(bnUtil.P.sub(1).toBuffer()))
      bnUtil.testBN(t, bn.redNeg(), BigNum(1))
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const bn = BN.fromBuffer(util.getMessage())
        if (bn.ucmp(BN.p) >= 0) bn.redIReduce()

        bnUtil.testBN(t, bn.redNeg(), bnUtil.P.sub(BigNum.fromBuffer(bn.toBuffer())))
        t.end()
      })
    }

    t.end()
  })

  t.test('redAdd', (t) => {
    t.test('source was not affected', (t) => {
      const a = BN.fromBuffer(util.getMessage())
      if (a.ucmp(BN.p) >= 0) a.redIReduce()
      const b = BN.fromBuffer(util.getTweak())
      if (b.ucmp(BN.p) >= 0) b.redIReduce()

      const b32a = a.toBuffer()
      bnUtil.testBN(t, a.redAdd(b), BigNum.fromBuffer(b32a).add(BigNum.fromBuffer(b.toBuffer())).mod(bnUtil.P))
      t.same(a.toBuffer(), b32a)
      t.end()
    })

    t.end()
  })

  t.test('redIAdd', (t) => {
    t.test('(p - 2) + 1 -> p - 1', (t) => {
      const a = BN.fromBuffer(bnUtil.fillZeros(bnUtil.P.sub(2).toBuffer()))
      const b = BN.fromBuffer(bnUtil.fillZeros(BigNum(1).toBuffer()))
      bnUtil.testBN(t, a.redAdd(b), bnUtil.P.sub(1))
      t.end()
    })

    t.test('(p - 1) + 1 -> 0', (t) => {
      const a = BN.fromBuffer(bnUtil.fillZeros(bnUtil.P.sub(1).toBuffer()))
      const b = BN.fromBuffer(bnUtil.fillZeros(BigNum(1).toBuffer()))
      bnUtil.testBN(t, a.redAdd(b), BigNum(0))
      t.end()
    })

    t.test('(p - 1) + 2 -> 1', (t) => {
      const a = BN.fromBuffer(bnUtil.fillZeros(bnUtil.P.sub(1).toBuffer()))
      const b = BN.fromBuffer(bnUtil.fillZeros(BigNum(2).toBuffer()))
      bnUtil.testBN(t, a.redAdd(b), BigNum(1))
      t.end()
    })

    t.test('(p - 1) + (p - 1) -> p - 2', (t) => {
      const a = BN.fromBuffer(bnUtil.fillZeros(bnUtil.P.sub(1).toBuffer()))
      const b = BN.fromBuffer(bnUtil.fillZeros(bnUtil.P.sub(1).toBuffer()))
      bnUtil.testBN(t, a.redAdd(b), bnUtil.P.sub(2))
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const a = BN.fromBuffer(util.getMessage())
        const b = BN.fromBuffer(util.getTweak())
        bnUtil.testBN(t, a.redAdd(b), BigNum.fromBuffer(a.toBuffer()).add(BigNum.fromBuffer(b.toBuffer())).mod(bnUtil.P))
        t.end()
      })
    }

    t.end()
  })

  t.test('redIAdd7', (t) => {
    t.test('(p - 8) + 7 -> p - 1', (t) => {
      const bn = BN.fromBuffer(bnUtil.P.sub(8).toBuffer())
      bnUtil.testBN(t, bn.redIAdd7(), bnUtil.P.sub(1))
      bnUtil.testBN(t, bn, bnUtil.P.sub(1))
      t.end()
    })

    t.test('(p - 7) + 7 -> 0', (t) => {
      const bn = BN.fromBuffer(bnUtil.P.sub(7).toBuffer())
      bnUtil.testBN(t, bn.redIAdd7(), BigNum(0))
      bnUtil.testBN(t, bn, BigNum(0))
      t.end()
    })

    t.test('(p - 1) + 7 -> 6', (t) => {
      const bn = BN.fromBuffer(bnUtil.P.sub(1).toBuffer())
      bnUtil.testBN(t, bn.redIAdd7(), BigNum(6))
      bnUtil.testBN(t, bn, BigNum(6))
      t.end()
    })

    t.end()
  })

  t.test('redSub', (t) => {
    t.test('source was not affected', (t) => {
      let a = BN.fromBuffer(util.getMessage())
      if (a.ucmp(BN.p) >= 0) a.redIReduce()
      let b = BN.fromBuffer(util.getTweak())
      if (b.ucmp(BN.p) >= 0) b.redIReduce()
      if (a.ucmp(b) === -1) {
        const tmp = a
        a = b
        b = tmp
      }

      const b32a = a.toBuffer()
      bnUtil.testBN(t, a.redSub(b), BigNum.fromBuffer(b32a).sub(BigNum.fromBuffer(b.toBuffer())).mod(bnUtil.P))
      t.same(a.toBuffer(), b32a)
      t.end()
    })

    t.end()
  })

  t.test('redISub', (t) => {
    t.test('0 - 1 -> p - 1', (t) => {
      const a = BN.fromNumber(0)
      const b = BN.fromNumber(1)
      bnUtil.testBN(t, a.redISub(b), bnUtil.P.sub(1))
      t.end()
    })

    t.test('(p - 2) - (p - 1) -> p - 1', (t) => {
      const a = BN.fromBuffer(bnUtil.fillZeros(bnUtil.P.sub(2).toBuffer()))
      const b = BN.fromBuffer(bnUtil.fillZeros(bnUtil.P.sub(1).toBuffer()))
      bnUtil.testBN(t, a.redISub(b), bnUtil.P.sub(1))
      t.end()
    })

    t.end()
  })

  t.test('redMul', (t) => {
    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const a = BN.fromBuffer(util.getMessage())
        if (a.ucmp(BN.p) >= 0) a.redIReduce()
        const b = BN.fromBuffer(util.getTweak())
        if (b.ucmp(BN.p) >= 0) b.redIReduce()

        const bnA = BigNum.fromBuffer(a.toBuffer())
        const bnB = BigNum.fromBuffer(b.toBuffer())
        bnUtil.testBN(t, a.redMul(b), bnA.mul(bnB).mod(bnUtil.P))
        t.end()
      })
    }

    t.end()
  })

  t.test('redSqr', (t) => {
    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const bn = BN.fromBuffer(util.getMessage())
        if (bn.ucmp(BN.p) >= 0) bn.redIReduce()

        bnUtil.testBN(t, bn.redSqr(), BigNum.fromBuffer(bn.toBuffer()).pow(2).mod(bnUtil.P))
        t.end()
      })
    }

    t.end()
  })

  t.test('redSqrt', (t) => {
    t.test('return zero for zero', (t) => {
      bnUtil.testBN(t, BN.fromNumber(0).redSqrt(), BigNum(0))
      t.end()
    })

    t.test('return null for quadratic nonresidue', (t) => {
      const b32 = Buffer.from('16e5f9d306371e9b876f04025fb8c8ed10f8b8864119a149803357e77bcdd3b1', 'hex')
      t.same(BN.fromBuffer(b32).redSqrt(), null)
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const bn = BN.fromBuffer(util.getMessage())
        if (bn.ucmp(BN.p) >= 0) bn.redIReduce()

        const result = bn.redSqrt()
        if (result !== null) bnUtil.testBN(t, bn, BigNum.fromBuffer(result.toBuffer()).pow(2).mod(bnUtil.P))

        t.end()
      })
    }

    t.end()
  })

  t.test('redInvm', (t) => {
    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const b32 = util.getMessage()
        const a = BN.fromBuffer(b32)
        if (a.ucmp(BN.p) >= 0) a.redIReduce()

        bnUtil.testBN(t, a.redInvm(), BigNum.fromBuffer(a.toBuffer()).invertm(bnUtil.P))
        t.end()
      })
    }

    t.end()
  })

  t.test('getNAF', (t) => {
    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const b32 = util.getMessage()
        const w = b32[0] % 10 + 1 // [1, 10]

        const naf = BN.fromBuffer(b32).getNAF(w)
        let power = BigNum(1)
        let bignum = BigNum(0)
        for (let i = 0; i < naf.length; ++i) {
          bignum = bignum.add(power.mul(naf[i]))
          power = power.mul(2)
        }

        t.same(bnUtil.fillZeros(bignum.toBuffer()), b32)
        t.end()
      })
    }

    t.end()
  })

  t.end()
})
