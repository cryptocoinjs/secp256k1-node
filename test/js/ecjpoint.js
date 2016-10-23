import test from 'tape'
import ECPoint from '../../es/js/ecpoint'
import ECJPoint from '../../es/js/ecjpoint'
import BN from '../../es/js/bn'

import * as util from '../util'

test('ECJPoint', (t) => {
  util.setSeed(util.env.SEED)

  t.test('neg', (t) => {
    t.test('return infinity for infinity', (t) => {
      const ecjpoint = new ECJPoint(null, null, null)
      t.true(ecjpoint.neg().inf)
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        const ecjpoint = ECPoint.fromPublicKey(publicKey).toECJPoint()
        const result = ecjpoint.neg()
        t.same(result.x.ucmp(ecjpoint.x), 0)
        t.same(result.y.ucmp(ecjpoint.y.redNeg()), 0)
        t.same(result.z.ucmp(ecjpoint.z), 0)
        t.end()
      })
    }

    t.end()
  })

  t.test('add', (t) => {
    t.test('O + P -> P', (t) => {
      const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      const ecjpoint1 = new ECJPoint(null, null, null)
      const ecjpoint2 = ECPoint.fromPublicKey(publicKey).toECJPoint()
      const result = ecjpoint1.add(ecjpoint2)
      t.same(result.x.ucmp(ecjpoint2.x), 0)
      t.same(result.y.ucmp(ecjpoint2.y), 0)
      t.same(result.z.ucmp(ecjpoint2.z), 0)
      t.end()
    })

    t.test('P + O -> P', (t) => {
      const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      const ecjpoint1 = ECPoint.fromPublicKey(publicKey).toECJPoint()
      const ecjpoint2 = new ECJPoint(null, null, null)
      const result = ecjpoint1.add(ecjpoint2)
      t.same(result.x.ucmp(ecjpoint1.x), 0)
      t.same(result.y.ucmp(ecjpoint1.y), 0)
      t.same(result.z.ucmp(ecjpoint1.z), 0)
      t.end()
    })

    t.test('P + P -> 2P', (t) => {
      const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      const ecjpoint = ECPoint.fromPublicKey(publicKey).toECJPoint()
      const expected = ecjpoint.dbl()
      const result = ecjpoint.add(ecjpoint)
      t.same(result.x.ucmp(expected.x), 0)
      t.same(result.y.ucmp(expected.y), 0)
      t.same(result.z.ucmp(expected.z), 0)
      t.end()
    })

    t.test('P + (-P) -> O', (t) => {
      const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      const ecjpoint = ECPoint.fromPublicKey(publicKey).toECJPoint()
      const result = ecjpoint.add(ecjpoint.neg())
      t.true(result.inf)
      t.end()
    })

    t.end()
  })

  t.test('mixedAdd', (t) => {
    t.test('O + P -> P', (t) => {
      const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      const ecjpoint = new ECJPoint(null, null, null)
      const ecpoint = ECPoint.fromPublicKey(publicKey)
      const result = ECPoint.fromECJPoint(ecjpoint.mixedAdd(ecpoint))
      t.same(result.x.ucmp(ecpoint.x), 0)
      t.same(result.y.ucmp(ecpoint.y), 0)
      t.end()
    })

    t.test('P + O -> P', (t) => {
      const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      const ecjpoint = ECPoint.fromPublicKey(publicKey).toECJPoint()
      const ecpoint = new ECPoint(null, null)
      const result = ecjpoint.mixedAdd(ecpoint)
      t.same(result.x.ucmp(ecjpoint.x), 0)
      t.same(result.y.ucmp(ecjpoint.y), 0)
      t.same(result.z.ucmp(ecjpoint.z), 0)
      t.end()
    })

    t.test('P + P -> 2P', (t) => {
      const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      const ecpoint = ECPoint.fromPublicKey(publicKey)
      const expected = ecpoint.toECJPoint().dbl()
      const result = ecpoint.toECJPoint().mixedAdd(ecpoint)
      t.same(result.x.ucmp(expected.x), 0)
      t.same(result.y.ucmp(expected.y), 0)
      t.same(result.z.ucmp(expected.z), 0)
      t.end()
    })

    t.test('P + (-P) -> O', (t) => {
      const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      const ecpoint = ECPoint.fromPublicKey(publicKey)
      const result = ecpoint.toECJPoint().mixedAdd(ecpoint.neg())
      t.true(result.inf)
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests (add/mixedAdd)', util.env.REPEAT, (t) => {
        const publicKey1 = util.getPublicKey(util.getPrivateKey()).compressed
        const ecjpoint = ECPoint.fromPublicKey(publicKey1).toECJPoint()
        const publicKey2 = util.getPublicKey(util.getPrivateKey()).compressed
        const ecpoint = ECPoint.fromPublicKey(publicKey2)
        const expected = ecjpoint.add(ecpoint.toECJPoint())
        const result = ecjpoint.mixedAdd(ecpoint)
        t.same(result.x.ucmp(expected.x), 0)
        t.same(result.y.ucmp(expected.y), 0)
        t.same(result.z.ucmp(expected.z), 0)
        t.end()
      })
    }

    t.end()
  })

  t.test('dbl', (t) => {
    t.test('doubling infinity', (t) => {
      const ecjpoint = new ECJPoint(null, null, null)
      t.true(ecjpoint.dbl().inf)
      t.end()
    })

    t.test('2P = 0 (y is same)', (t) => {
      const bn = BN.fromBuffer(util.getMessage())
      const ecjpoint = new ECPoint(bn, BN.fromNumber(0)).toECJPoint()
      t.true(ecjpoint.dbl().inf)
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        const ecjpoint = ECPoint.fromPublicKey(publicKey).toECJPoint()
        const expected = ecjpoint.add(ecjpoint)
        const result = ecjpoint.dbl()
        t.same(result.x.ucmp(expected.x), 0)
        t.same(result.y.ucmp(expected.y), 0)
        t.same(result.z.ucmp(expected.z), 0)
        t.end()
      })
    }

    t.end()
  })

  t.test('dblp', (t) => {
    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests (pow from 0 to 10)', util.env.REPEAT, (t) => {
        const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        const ecjpoint = ECPoint.fromPublicKey(publicKey).toECJPoint()
        for (let i = 0, expected = ecjpoint; i < 10; ++i, expected = expected.dbl()) {
          const result = ecjpoint.dblp(i)
          t.same(result.x.ucmp(expected.x), 0)
          t.same(result.y.ucmp(expected.y), 0)
          t.same(result.z.ucmp(expected.z), 0)
        }

        t.end()
      })
    }

    t.end()
  })

  t.end()
})
