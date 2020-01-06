const util = require('./util')

module.exports = (t, secp256k1) => {
  t.test('privateKeyVerify', (t) => {
    t.test('arg: invalid private key', (t) => {
      t.throws(() => {
        secp256k1.privateKeyVerify(null)
      }, /^Error: Expected private key to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey().slice(1)
        secp256k1.privateKeyVerify(privateKey)
      }, /^Error: Expected private key to be an Uint8Array with length 32$/, 'should have length 32')

      t.end()
    })

    t.test('validate invalid private keys', (t) => {
      const fixtures = [{
        privateKey: util.BN_ZERO.toArrayLike(Buffer, 'be', 32),
        msg: '0 should be invalid private key'
      }, {
        privateKey: util.ec.curve.n.toArrayLike(Buffer, 'be', 32),
        msg: 'N should be invalid private key'
      }]

      for (const { privateKey, msg } of fixtures) {
        t.false(secp256k1.privateKeyVerify(privateKey), msg)
      }

      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, (t) => {
      const privateKey = util.getPrivateKey()
      t.true(secp256k1.privateKeyVerify(privateKey), 'should be a valid private key')
    })

    t.end()
  })

  t.test('privateKeyNegate', (t) => {
    t.test('arg: invalid private key', (t) => {
      t.throws(() => {
        secp256k1.privateKeyNegate(null)
      }, /^Error: Expected private key to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey().slice(1)
        secp256k1.privateKeyNegate(privateKey)
      }, /^Error: Expected private key to be an Uint8Array with length 32$/, 'should have length 32')

      t.end()
    })

    t.test('negate valid private keys', (t) => {
      const fixtures = [{
        privateKey: util.BN_ZERO.toArrayLike(Buffer, 'be', 32),
        expected: Buffer.allocUnsafe(32).fill(0x00),
        msg: 'negate 0 private key'
      }, {
        privateKey: util.ec.curve.n.toArrayLike(Buffer, 'be', 32),
        expected: Buffer.allocUnsafe(32).fill(0x00),
        msg: 'negate N private key'
      }, {
        privateKey: util.ec.curve.n.addn(10).toArrayLike(Buffer, 'be', 32),
        expected: util.ec.curve.n.subn(10).toArrayLike(Buffer, 'be', 32),
        msg: 'negate overflowed private key'
      }]

      for (const { privateKey, expected, msg } of fixtures) {
        const negated = secp256k1.privateKeyNegate(privateKey)
        t.same(negated, expected, msg)
      }

      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, (t) => {
      const privateKey = util.getPrivateKey()

      const expected = util.ec.curve.n.sub(new util.BN(privateKey))
      const result = secp256k1.privateKeyNegate(privateKey)

      t.same(result.toString('hex'), expected.toString('hex', 64))
    })

    t.end()
  })

  t.test('privateKeyTweakAdd', (t) => {
    t.test('arg: invalid private key', (t) => {
      t.throws(() => {
        const tweak = util.getTweak()
        secp256k1.privateKeyTweakAdd(null, tweak)
      }, /^Error: Expected private key to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey().slice(1)
        const tweak = util.getTweak()
        secp256k1.privateKeyTweakAdd(privateKey, tweak)
      }, /^Error: Expected private key to be an Uint8Array with length 32$/, 'should have length 32')

      t.end()
    })

    t.test('arg: invalid tweak', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        secp256k1.privateKeyTweakAdd(privateKey, null)
      }, /^Error: Expected tweak to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const tweak = util.getTweak().slice(1)
        secp256k1.privateKeyTweakAdd(privateKey, tweak)
      }, /^Error: Expected tweak to be an Uint8Array with length 32$/, 'should have length 32')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const tweak = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
        secp256k1.privateKeyTweakAdd(privateKey, tweak)
      }, /^Error: The tweak was out of range or the resulted private key is invalid$/, 'tweak overflow')

      t.end()
    })

    t.test('should throw if result is invalid (zero private key: (N - 1) + 1', (t) => {
      t.throws(() => {
        const privateKey = util.ec.curve.n.sub(util.BN_ONE).toArrayLike(Buffer, 'be', 32)
        const tweak = util.BN_ONE.toArrayLike(Buffer, 'be', 32)
        secp256k1.privateKeyTweakAdd(privateKey, tweak)
      }, /^Error: The tweak was out of range or the resulted private key is invalid$/)
      t.end()
    })

    t.test('should be OK without overflow', (t) => {
      const privateKey = util.BN_ONE.toArrayLike(Buffer, 'be', 32)
      const tweak = util.BN_ONE.toArrayLike(Buffer, 'be', 32)
      const result = secp256k1.privateKeyTweakAdd(privateKey, tweak, Buffer.alloc)
      t.same(result, new util.BN(2).toArrayLike(Buffer, 'be', 32))
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, (t) => {
      const privateKey = util.getPrivateKey()
      const tweak = util.getTweak()

      const expected = new util.BN(privateKey).add(new util.BN(tweak)).mod(util.ec.curve.n)
      if (expected.cmp(util.BN_ZERO) === 0) {
        t.throws(() => {
          secp256k1.privateKeyTweakAdd(privateKey, tweak)
        }, /^Error: The tweak was out of range or the resulted private key is invalid$/)
      } else {
        const result = secp256k1.privateKeyTweakAdd(privateKey, tweak)
        t.same(result, expected.toArrayLike(Buffer, 'be', 32))
      }
    })

    t.end()
  })

  t.test('privateKeyTweakMul', (t) => {
    t.test('arg: invalid private key', (t) => {
      t.throws(() => {
        const tweak = util.getTweak()
        secp256k1.privateKeyTweakMul(null, tweak)
      }, /^Error: Expected private key to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey().slice(1)
        const tweak = util.getTweak()
        secp256k1.privateKeyTweakMul(privateKey, tweak)
      }, /^Error: Expected private key to be an Uint8Array with length 32$/, 'should have length 32')

      t.end()
    })

    t.test('arg: invalid tweak', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        secp256k1.privateKeyTweakMul(privateKey, null)
      }, /^Error: Expected tweak to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const tweak = util.getTweak().slice(1)
        secp256k1.privateKeyTweakMul(privateKey, tweak)
      }, /^Error: Expected tweak to be an Uint8Array with length 32$/, 'should have length 32')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const tweak = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
        secp256k1.privateKeyTweakMul(privateKey, tweak)
      }, /^Error: The tweak was out of range or equal to zero$/, 'tweak should be less than N')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const tweak = util.BN_ZERO.toArrayLike(Buffer, 'be', 32)
        secp256k1.privateKeyTweakMul(privateKey, tweak)
      }, /^Error: The tweak was out of range or equal to zero$/, 'tweak should not be equal to 0')

      t.end()
    })

    t.test('should be OK without overflow', (t) => {
      const privateKey = util.BN_ONE.toArrayLike(Buffer, 'be', 32)
      const tweak = util.BN_ONE.toArrayLike(Buffer, 'be', 32)
      const result = secp256k1.privateKeyTweakMul(privateKey, tweak, Buffer.alloc)
      t.same(result, util.BN_ONE.toArrayLike(Buffer, 'be', 32))
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, (t) => {
      const privateKey = util.getPrivateKey()
      const tweak = util.getTweak()

      if (new util.BN(tweak).cmp(util.BN_ZERO) === 0) {
        t.throws(() => {
          secp256k1.privateKeyTweakMul(privateKey, tweak)
        }, /^Error: The tweak was out of range or equal to zero$/)
      } else {
        const expected = new util.BN(privateKey).mul(new util.BN(tweak)).mod(util.ec.curve.n)
        const result = secp256k1.privateKeyTweakMul(privateKey, tweak)
        t.same(result, expected.toArrayLike(Buffer, 'be', 32))
      }
    })

    t.end()
  })
}
