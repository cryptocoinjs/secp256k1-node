import test from 'tape'
import ECPoint from '../../es/js/ecpoint'
import ECJPoint from '../../es/js/ecjpoint'
import BN from '../../es/js/bn'

import * as util from '../util'

const pbuf = Buffer.from('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 'hex')
const zerobuf = Buffer.from('0000000000000000000000000000000000000000000000000000000000000000', 'hex')
const onebuf = Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex')

test('ECPoint', (t) => {
  util.setSeed(util.env.SEED)

  t.test('ECPoint.fromPublicKey', (t) => {
    t.test('length from 0 to 100 except 33 and 65', (t) => {
      for (let size = 0; size < 100; ++size) {
        if (size === 33 || size === 65) continue
        const publicKey = Buffer.allocUnsafe(size)
        t.same(ECPoint.fromPublicKey(publicKey), null)
      }

      t.end()
    })

    t.test('short key', (t) => {
      t.test('length eq 33, first byte from 0 to 255, but not 2 and 3', (t) => {
        const publicKey = Buffer.allocUnsafe(33)
        for (let first = 0; first < 256; ++first) {
          if (first === 0x02 || first === 0x03) continue
          publicKey[0] = first
          t.same(ECPoint.fromPublicKey(publicKey), null)
        }

        t.end()
      })

      t.test('x eq p', (t) => {
        const publicKey = Buffer.concat([Buffer.from([0x02]), pbuf])
        t.same(ECPoint.fromPublicKey(publicKey), null)
        t.end()
      })

      t.test('y is quadratic nonresidue', (t) => {
        const publicKey = Buffer.from('02fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140', 'hex')
        t.same(ECPoint.fromPublicKey(publicKey), null)
        t.end()
      })

      t.test('0x03 should change y sign', (t) => {
        const p1 = ECPoint.fromPublicKey(Buffer.concat([Buffer.from([0x02]), onebuf]))
        const p2 = ECPoint.fromPublicKey(Buffer.concat([Buffer.from([0x03]), onebuf]))

        t.notDeepEqual(p1, null)
        t.notDeepEqual(p2, null)
        t.same(p1.x.ucmp(p2.x), 0)
        t.same(p1.y.redNeg().ucmp(p2.y), 0)
        t.end()
      })

      t.end()
    })

    t.test('full key', (t) => {
      t.test('length eq 65, first byte from 0 to 255, but not 4, 6 and 7', (t) => {
        const publicKey = Buffer.allocUnsafe(65)
        for (let first = 0; first < 256; ++first) {
          if (first === 0x04 || first === 0x06 || first === 0x07) continue
          publicKey[0] = first
          t.same(ECPoint.fromPublicKey(publicKey), null)
        }

        t.end()
      })

      t.test('x eq p', (t) => {
        const publicKey = Buffer.concat([Buffer.from([0x04]), pbuf, zerobuf])
        t.same(ECPoint.fromPublicKey(publicKey), null)
        t.end()
      })

      t.test('y eq p', (t) => {
        const publicKey = Buffer.concat([Buffer.from([0x04]), zerobuf, pbuf])
        t.same(ECPoint.fromPublicKey(publicKey), null)
        t.end()
      })

      t.test('first byte is 0x06, y is event', (t) => {
        const publicKey = Buffer.concat([Buffer.from([0x06]), zerobuf, zerobuf])
        t.same(ECPoint.fromPublicKey(publicKey), null)
        t.end()
      })

      t.test('first byte is 0x06, y is odd', (t) => {
        const publicKey = Buffer.concat([Buffer.from([0x07]), zerobuf, onebuf])
        t.same(ECPoint.fromPublicKey(publicKey), null)
        t.end()
      })

      t.test('x*x*x + 7 != y*y', (t) => {
        const publicKey = Buffer.concat([Buffer.from([0x04]), zerobuf, zerobuf])
        t.same(ECPoint.fromPublicKey(publicKey), null)
        t.end()
      })

      t.end()
    })

    t.end()
  })

  t.test('toPublicKey', (t) => {
    t.test('compressed & y is even', (t) => {
      const p = new ECPoint(BN.fromBuffer(zerobuf), BN.fromBuffer(zerobuf))
      const publicKey = p.toPublicKey(true)
      t.same(publicKey, Buffer.concat([Buffer.from([0x02]), zerobuf]))
      t.end()
    })

    t.test('compressed & y is odd', (t) => {
      const p = new ECPoint(BN.fromBuffer(zerobuf), BN.fromBuffer(onebuf))
      const publicKey = p.toPublicKey(true)
      t.same(publicKey, Buffer.concat([Buffer.from([0x03]), zerobuf]))
      t.end()
    })

    t.test('uncompressed', (t) => {
      const p = new ECPoint(BN.fromBuffer(zerobuf), BN.fromBuffer(zerobuf))
      const publicKey = p.toPublicKey(false)
      t.same(publicKey, Buffer.concat([Buffer.from([0x04]), zerobuf, zerobuf]))
      t.end()
    })

    t.end()
  })

  t.test('fromECJPoint/toECJPoint', (t) => {
    t.test('fromECJPoint return infinity for infinity', (t) => {
      var ecjpoint = new ECJPoint(null, null, null)
      var ecpoint = ECPoint.fromECJPoint(ecjpoint)
      t.true(ecpoint.inf)
      t.end()
    })

    t.test('toECJPoint return infinity for infinity', (t) => {
      var ecpoint = new ECPoint(null, null)
      var ecjpoint = ecpoint.toECJPoint()
      t.true(ecjpoint.inf)
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        const ecpoint = ECPoint.fromPublicKey(publicKey)
        const ecpoint2 = ECPoint.fromECJPoint(ecpoint.toECJPoint())
        t.same(ecpoint.x.ucmp(ecpoint2.x), 0)
        t.same(ecpoint.y.ucmp(ecpoint2.y), 0)
        t.end()
      })
    }

    t.end()
  })

  t.test('neg', (t) => {
    t.test('ECPoint, return infinity for infinity', (t) => {
      const ecpoint = new ECPoint(null, null)
      t.true(ecpoint.neg().inf)
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        const ecpoint = ECPoint.fromPublicKey(publicKey)
        const result = ecpoint.neg()
        t.same(result.x.ucmp(ecpoint.x), 0)
        t.same(result.y.ucmp(ecpoint.y.redNeg()), 0)
        t.end()
      })
    }

    t.end()
  })

  t.test('add', (t) => {
    t.test('O + P -> P', (t) => {
      const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      const ecpoint1 = new ECPoint(null, null)
      const ecpoint2 = ECPoint.fromPublicKey(publicKey)
      const result = ecpoint1.add(ecpoint2)
      t.same(result.x.ucmp(ecpoint2.x), 0)
      t.same(result.y.ucmp(ecpoint2.y), 0)
      t.end()
    })

    t.test('P + O -> P', (t) => {
      const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      const ecpoint1 = ECPoint.fromPublicKey(publicKey)
      const ecpoint2 = new ECPoint(null, null)
      const result = ecpoint1.add(ecpoint2)
      t.same(result.x.ucmp(ecpoint1.x), 0)
      t.same(result.y.ucmp(ecpoint1.y), 0)
      t.end()
    })

    t.test('P + P -> 2P', (t) => {
      const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      const ecpoint = ECPoint.fromPublicKey(publicKey)
      const expected = ecpoint.dbl()
      const result = ecpoint.add(ecpoint)
      t.same(result.x.ucmp(expected.x), 0)
      t.same(result.y.ucmp(expected.y), 0)
      t.end()
    })

    t.test('P + (-P) -> O', (t) => {
      const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
      const ecpoint = ECPoint.fromPublicKey(publicKey)
      const result = ecpoint.add(ecpoint.neg())
      t.true(result.inf)
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests (compare with ECJPoint)', util.env.REPEAT, (t) => {
        const publicKey1 = util.getPublicKey(util.getPrivateKey()).compressed
        const ecpoint1 = ECPoint.fromPublicKey(publicKey1)
        const publicKey2 = util.getPublicKey(util.getPrivateKey()).compressed
        const ecpoint2 = ECPoint.fromPublicKey(publicKey2)
        const expected = ECPoint.fromECJPoint(ecpoint1.toECJPoint().add(ecpoint2.toECJPoint()))
        const result = ecpoint1.add(ecpoint2)
        t.same(result.x.ucmp(expected.x), 0)
        t.same(result.y.ucmp(expected.y), 0)
        t.end()
      })
    }

    t.end()
  })

  t.test('dbl', (t) => {
    t.test('doubling infinity', (t) => {
      const ecpoint = new ECPoint(null, null)
      t.true(ecpoint.dbl().inf)
      t.end()
    })

    t.test('2P = 0 (y is same)', (t) => {
      const bn = BN.fromBuffer(util.getMessage())
      const ecpoint = new ECPoint(bn, BN.fromNumber(0))
      t.true(ecpoint.dbl().inf)
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        const ecpoint = ECPoint.fromPublicKey(publicKey)
        const expected = ecpoint.add(ecpoint)
        const result = ecpoint.dbl()
        t.same(result.x.ucmp(expected.x), 0)
        t.same(result.y.ucmp(expected.y), 0)
        t.end()
      })
    }

    t.end()
  })

  t.end()
})
