const BN = require('bn.js')
const util = require('./util')

module.exports = (t, secp256k1) => {
  t.test('privateKeyVerify', (t) => {
    t.test('should be an Uint8Array', (t) => {
      t.throws(() => {
        secp256k1.privateKeyVerify(null)
      }, /^Error: Expected private key to be an Uint8Array$/)
      t.end()
    })

    t.test('invalid length', (t) => {
      t.throws(() => {
        secp256k1.privateKeyVerify(util.getPrivateKey().slice(1))
      }, /^Error: Expected private key to be an Uint8Array with length 32$/)
      t.end()
    })

    t.test('zero key', (t) => {
      const privateKey = util.BN_ZERO.toArrayLike(Buffer, 'be', 32)
      t.false(secp256k1.privateKeyVerify(privateKey))
      t.end()
    })

    t.test('equal to N', (t) => {
      const privateKey = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
      t.false(secp256k1.privateKeyVerify(privateKey))
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, (t) => {
      const privateKey = util.getPrivateKey()
      t.true(secp256k1.privateKeyVerify(privateKey))
    })

    t.end()
  })

  t.test('privateKeyNegate', (t) => {
    t.test('private key should be an Uint8Array', (t) => {
      t.throws(() => {
        secp256k1.privateKeyNegate(null)
      }, /^Error: Expected private key to be an Uint8Array$/)
      t.end()
    })

    t.test('private key length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey().slice(1)
        secp256k1.privateKeyNegate(privateKey)
      }, /^Error: Expected private key to be an Uint8Array with length 32$/)
      t.end()
    })

    t.test('private key is 0', (t) => {
      const privateKey = util.BN_ZERO.toArrayLike(Buffer, 'be', 32)

      const expected = Buffer.alloc(32)
      const result = secp256k1.privateKeyNegate(privateKey)
      t.same(result, expected)

      t.end()
    })

    t.test('private key equal to N', (t) => {
      const privateKey = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)

      const expected = Buffer.alloc(32)
      const result = secp256k1.privateKeyNegate(privateKey)
      t.same(result, expected)

      t.end()
    })

    t.test('private key overflow', (t) => {
      const privateKey = util.ec.curve.n.addn(10).toArrayLike(Buffer, 'be', 32)

      const expected = util.ec.curve.n.subn(10).toArrayLike(Buffer, 'be', 32)
      const result = secp256k1.privateKeyNegate(privateKey)
      t.same(result, expected)

      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, (t) => {
      const privateKey = util.getPrivateKey()

      const expected = util.ec.curve.n.sub(new BN(privateKey))
      const result = secp256k1.privateKeyNegate(privateKey)
      t.same(result.toString('hex'), expected.toString('hex', 64))
    })

    t.end()
  })

  t.test('privateKeyTweakAdd', (t) => {
    t.test('private key should be an Uint8Array', (t) => {
      t.throws(() => {
        const tweak = util.getTweak()
        secp256k1.privateKeyTweakAdd(null, tweak)
      }, /^Error: Expected private key to be an Uint8Array$/)
      t.end()
    })

    t.test('private key length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey().slice(1)
        const tweak = util.getTweak()
        secp256k1.privateKeyTweakAdd(privateKey, tweak)
      }, /^Error: Expected private key to be an Uint8Array with length 32$/)
      t.end()
    })

    t.test('tweak should be an Uint8Array', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        secp256k1.privateKeyTweakAdd(privateKey, null)
      }, /^Error: Expected tweak to be an Uint8Array$/)
      t.end()
    })

    t.test('tweak length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const tweak = util.getTweak().slice(1)
        secp256k1.privateKeyTweakAdd(privateKey, tweak)
      }, /^Error: Expected tweak to be an Uint8Array with length 32$/)
      t.end()
    })

    t.test('tweak overflow', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const tweak = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
        secp256k1.privateKeyTweakAdd(privateKey, tweak)
      }, /^Error: The tweak was out of range or the resulted private key is invalid$/)
      t.end()
    })

    t.test('result is zero: (N - 1) + 1', (t) => {
      t.throws(() => {
        const privateKey = util.ec.curve.n.sub(util.BN_ONE).toArrayLike(Buffer, 'be', 32)
        const tweak = util.BN_ONE.toArrayLike(Buffer, 'be', 32)
        secp256k1.privateKeyTweakAdd(privateKey, tweak)
      }, /^Error: The tweak was out of range or the resulted private key is invalid$/)
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, (t) => {
      const privateKey = util.getPrivateKey()
      const tweak = util.getTweak()

      const expected = new BN(privateKey).add(new BN(tweak)).mod(util.ec.curve.n)
      if (expected.cmp(util.BN_ZERO) === 0) {
        t.throws(() => {
          secp256k1.privateKeyTweakAdd(privateKey, tweak)
        }, /^Error: The tweak was out of range or the resulted private key is invalid$/)
      } else {
        const result = secp256k1.privateKeyTweakAdd(privateKey, tweak)
        t.same(result.toString('hex'), expected.toString(16, 64))
      }
    })

    t.end()
  })

  t.test('privateKeyTweakMul', (t) => {
    t.test('private key should be an Uint8Array', (t) => {
      t.throws(() => {
        const tweak = util.getTweak()
        secp256k1.privateKeyTweakMul(null, tweak)
      }, /^Error: Expected private key to be an Uint8Array$/)
      t.end()
    })

    t.test('private key length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey().slice(1)
        const tweak = util.getTweak()
        secp256k1.privateKeyTweakMul(privateKey, tweak)
      }, /^Error: Expected private key to be an Uint8Array with length 32$/)
      t.end()
    })

    t.test('tweak should be an Uint8Array', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        secp256k1.privateKeyTweakMul(privateKey, null)
      }, /^Error: Expected tweak to be an Uint8Array$/)
      t.end()
    })

    t.test('tweak length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const tweak = util.getTweak().slice(1)
        secp256k1.privateKeyTweakMul(privateKey, tweak)
      }, /^Error: Expected tweak to be an Uint8Array with length 32$/)
      t.end()
    })

    t.test('tweak equal N', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const tweak = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
        secp256k1.privateKeyTweakMul(privateKey, tweak)
      }, /^Error: The tweak was out of range or equal to zero$/)
      t.end()
    })

    t.test('tweak is 0', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const tweak = util.BN_ZERO.toArrayLike(Buffer, 'be', 32)
        secp256k1.privateKeyTweakMul(privateKey, tweak)
      }, /^Error: The tweak was out of range or equal to zero$/)
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, (t) => {
      const privateKey = util.getPrivateKey()
      const tweak = util.getTweak()

      if (new BN(tweak).cmp(util.BN_ZERO) === 0) {
        t.throws(() => {
          secp256k1.privateKeyTweakMul(privateKey, tweak)
        }, /^Error: The tweak was out of range or equal to zero$/)
      } else {
        const expected = new BN(privateKey).mul(new BN(tweak)).mod(util.ec.curve.n)
        const result = secp256k1.privateKeyTweakMul(privateKey, tweak)
        t.same(result.toString('hex'), expected.toString(16, 64))
      }
    })

    t.end()
  })
}
