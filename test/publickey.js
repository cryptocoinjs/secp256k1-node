import BN from 'bn.js'
import * as util from './util'

const messages = util.messages

export default function (t, secp256k1) {
  t.test('publicKey.create', (t) => {
    t.test('should be a Buffer', (t) => {
      t.throws(() => {
        secp256k1.publicKey.create(null)
      }, new RegExp(`^TypeError: ${messages.EC_PRIVATE_KEY_TYPE_INVALID}$`))
      t.end()
    })

    t.test('invalid length', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey().slice(1)
        secp256k1.publicKey.create(privateKey)
      }, new RegExp(`^RangeError: ${messages.EC_PRIVATE_KEY_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('overflow', (t) => {
      t.throws(() => {
        const privateKey = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
        secp256k1.publicKey.create(privateKey)
      }, new RegExp(`^Error: ${messages.EC_PUBLIC_KEY_CREATE_FAIL}$`))
      t.end()
    })

    t.test('equal zero', (t) => {
      t.throws(() => {
        const privateKey = util.BN_ZERO.toArrayLike(Buffer, 'be', 32)
        secp256k1.publicKey.create(privateKey)
      }, new RegExp(`^Error: ${messages.EC_PUBLIC_KEY_CREATE_FAIL}$`))
      t.end()
    })

    t.test('compressed should be a boolean', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        secp256k1.publicKey.create(privateKey, null)
      }, new RegExp(`^TypeError: ${messages.COMPRESSED_TYPE_INVALID}$`))
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const privateKey = util.getPrivateKey()
        const expected = util.getPublicKey(privateKey)

        const compressed = secp256k1.publicKey.create(privateKey, true)
        t.same(compressed, expected.compressed)

        const uncompressed = secp256k1.publicKey.create(privateKey, false)
        t.same(uncompressed, expected.uncompressed)

        t.end()
      })
    }

    t.end()
  })

  t.test('publicKey.convert', (t) => {
    t.test('should be a Buffer', (t) => {
      t.throws(() => {
        secp256k1.publicKey.convert(null)
      }, new RegExp(`^TypeError: ${messages.EC_PUBLIC_KEY_TYPE_INVALID}$`))
      t.end()
    })

    t.test('length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        secp256k1.publicKey.convert(publicKey)
      }, new RegExp(`^RangeError: ${messages.EC_PUBLIC_KEY_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('compressed should be a boolean', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.publicKey.convert(publicKey, null)
      }, new RegExp(`^TypeError: ${messages.COMPRESSED_TYPE_INVALID}$`))
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const privateKey = util.getPrivateKey()
        const expected = util.getPublicKey(privateKey)

        const compressed = secp256k1.publicKey.convert(expected.uncompressed, true)
        t.same(compressed, expected.compressed)

        const uncompressed = secp256k1.publicKey.convert(expected.compressed, false)
        t.same(uncompressed, expected.uncompressed)

        t.end()
      })
    }

    t.end()
  })

  t.test('publicKey.verify', (t) => {
    t.test('should be a Buffer', (t) => {
      t.throws(() => {
        secp256k1.publicKey.verify(null)
      }, new RegExp(`^TypeError: ${messages.EC_PUBLIC_KEY_TYPE_INVALID}$`))
      t.end()
    })

    t.test('invalid length', (t) => {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
      t.false(secp256k1.publicKey.verify(publicKey))
      t.end()
    })

    t.test('invalid first byte', (t) => {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed
      publicKey[0] = 0x01
      t.false(secp256k1.publicKey.verify(publicKey))
      t.end()
    })

    t.test('x overflow (first byte is 0x03)', (t) => {
      const publicKey = Buffer.concat([
        Buffer.from([ 0x03 ]),
        util.ec.curve.p.toArrayLike(Buffer, 'be', 32)
      ])
      t.false(secp256k1.publicKey.verify(publicKey))
      t.end()
    })

    t.test('x overflow', (t) => {
      const publicKey = Buffer.concat([
        Buffer.from([ 0x04 ]),
        util.ec.curve.p.toArrayLike(Buffer, 'be', 32)
      ])
      t.false(secp256k1.publicKey.verify(publicKey))
      t.end()
    })

    t.test('y overflow', (t) => {
      const publicKey = Buffer.concat([
        Buffer.from([ 0x04 ]),
        Buffer.allocUnsafe(32),
        util.ec.curve.p.toArrayLike(Buffer, 'be', 32)
      ])
      t.false(secp256k1.publicKey.verify(publicKey))
      t.end()
    })

    t.test('y is even, first byte is 0x07', (t) => {
      const publicKey = Buffer.concat([
        Buffer.from([ 0x07 ]),
        Buffer.allocUnsafe(32),
        util.ec.curve.p.subn(1).toArrayLike(Buffer, 'be', 32)
      ])
      t.false(secp256k1.publicKey.verify(publicKey))
      t.end()
    })

    t.test('y**2 !== x*x*x + 7', (t) => {
      const publicKey = Buffer.concat([Buffer.from([ 0x04 ]), util.getTweak(), util.getTweak()])
      t.false(secp256k1.publicKey.verify(publicKey))
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey)
        t.true(secp256k1.publicKey.verify(publicKey.compressed))
        t.true(secp256k1.publicKey.verify(publicKey.uncompressed))
        t.end()
      })
    }

    t.end()
  })

  t.test('publicKey.tweakAdd', (t) => {
    t.test('public key should be a Buffer', (t) => {
      t.throws(() => {
        const tweak = util.getTweak()
        secp256k1.publicKey.tweakAdd(null, tweak)
      }, new RegExp(`^TypeError: ${messages.EC_PUBLIC_KEY_TYPE_INVALID}$`))
      t.end()
    })

    t.test('public key length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        const tweak = util.getTweak()
        secp256k1.publicKey.tweakAdd(publicKey, tweak)
      }, new RegExp(`^RangeError: ${messages.EC_PUBLIC_KEY_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('public key is invalid (version is 0x01)', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        publicKey[0] = 0x01
        const tweak = util.getTweak()
        secp256k1.publicKey.tweakAdd(publicKey, tweak)
      }, new RegExp(`^Error: ${messages.EC_PUBLIC_KEY_PARSE_FAIL}$`))
      t.end()
    })

    t.test('tweak should be a Buffer', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.publicKey.tweakAdd(publicKey, null)
      }, new RegExp(`^TypeError: ${messages.TWEAK_TYPE_INVALID}$`))
      t.end()
    })

    t.test('tweak length length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        const tweak = util.getTweak().slice(1)
        secp256k1.publicKey.tweakAdd(publicKey, tweak)
      }, new RegExp(`^RangeError: ${messages.TWEAK_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('compressed should be a boolean', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        const tweak = util.getTweak()
        secp256k1.publicKey.tweakAdd(publicKey, tweak, null)
      }, new RegExp(`^TypeError: ${messages.COMPRESSED_TYPE_INVALID}$`))
      t.end()
    })

    t.test('tweak overflow', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        const tweak = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
        secp256k1.publicKey.tweakAdd(publicKey, tweak)
      }, new RegExp(`^Error: ${messages.EC_PUBLIC_KEY_TWEAK_ADD_FAIL}$`))
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const privateKey = util.getPrivateKey()
        const tweak = util.getTweak()

        const publicPoint = util.ec.g.mul(new BN(privateKey))
        const publicKey = Buffer.from(publicPoint.encode(null, true))
        const expected = util.ec.g.mul(new BN(tweak)).add(publicPoint)

        const compressed = secp256k1.publicKey.tweakAdd(publicKey, tweak, true)
        t.same(compressed.toString('hex'), expected.encode('hex', true))

        const uncompressed = secp256k1.publicKey.tweakAdd(publicKey, tweak, false)
        t.same(uncompressed.toString('hex'), expected.encode('hex', false))

        t.end()
      })
    }

    t.end()
  })

  t.test('publicKey.tweakMul', (t) => {
    t.test('public key should be a Buffer', (t) => {
      t.throws(() => {
        const tweak = util.getTweak()
        secp256k1.publicKey.tweakMul(null, tweak)
      }, new RegExp(`^TypeError: ${messages.EC_PUBLIC_KEY_TYPE_INVALID}$`))
      t.end()
    })

    t.test('public key length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        const tweak = util.getTweak()
        secp256k1.publicKey.tweakMul(publicKey, tweak)
      }, new RegExp(`^RangeError: ${messages.EC_PUBLIC_KEY_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('public key is invalid (version is 0x01)', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        publicKey[0] = 0x01
        const tweak = util.getTweak()
        secp256k1.publicKey.tweakMul(publicKey, tweak)
      }, new RegExp(`^Error: ${messages.EC_PUBLIC_KEY_PARSE_FAIL}$`))
      t.end()
    })

    t.test('tweak should be a Buffer', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.publicKey.tweakMul(publicKey, null)
      }, new RegExp(`^TypeError: ${messages.TWEAK_TYPE_INVALID}$`))
      t.end()
    })

    t.test('tweak length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        const tweak = util.getTweak().slice(1)
        secp256k1.publicKey.tweakMul(publicKey, tweak)
      }, new RegExp(`^RangeError: ${messages.TWEAK_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('compressed should be a boolean', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        const tweak = util.getTweak()
        secp256k1.publicKey.tweakMul(publicKey, tweak, null)
      }, new RegExp(`^TypeError: ${messages.COMPRESSED_TYPE_INVALID}$`))
      t.end()
    })

    t.test('tweak is zero', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        const tweak = util.BN_ZERO.toArrayLike(Buffer, 'be', 32)
        secp256k1.publicKey.tweakMul(publicKey, tweak)
      }, new RegExp(`^Error: ${messages.EC_PUBLIC_KEY_TWEAK_MUL_FAIL}$`))
      t.end()
    })

    t.test('tweak overflow', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        const tweak = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
        secp256k1.publicKey.tweakMul(publicKey, tweak)
      }, new RegExp(`^Error: ${messages.EC_PUBLIC_KEY_TWEAK_MUL_FAIL}$`))
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const privateKey = util.getPrivateKey()
        const publicPoint = util.ec.g.mul(new BN(privateKey))
        const publicKey = Buffer.from(publicPoint.encode(null, true))
        const tweak = util.getTweak()

        if (new BN(tweak).cmp(util.BN_ZERO) === 0) {
          t.throws(() => {
            secp256k1.publicKey.tweakMul(publicKey, tweak)
          }, new RegExp(`^Error: ${messages.EC_PUBLIC_KEY_TWEAK_MUL_FAIL}$`))
        } else {
          const expected = publicPoint.mul(tweak)

          const compressed = secp256k1.publicKey.tweakMul(publicKey, tweak, true)
          t.same(compressed.toString('hex'), expected.encode('hex', true))

          const uncompressed = secp256k1.publicKey.tweakMul(publicKey, tweak, false)
          t.same(uncompressed.toString('hex'), expected.encode('hex', false))
        }

        t.end()
      })
    }
  })

  t.test('publicKey.combine', (t) => {
    t.test('public keys should be an Array', (t) => {
      t.throws(() => {
        secp256k1.publicKey.combine(null)
      }, new RegExp(`^TypeError: ${messages.EC_PUBLIC_KEYS_TYPE_INVALID}$`))
      t.end()
    })

    t.test('public keys should have length greater that zero', (t) => {
      t.throws(() => {
        secp256k1.publicKey.combine([])
      }, new RegExp(`^RangeError: ${messages.EC_PUBLIC_KEYS_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('public key should be a Buffer', (t) => {
      t.throws(() => {
        secp256k1.publicKey.combine([null])
      }, new RegExp(`^TypeError: ${messages.EC_PUBLIC_KEY_TYPE_INVALID}$`))
      t.end()
    })

    t.test('public key length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        secp256k1.publicKey.combine([publicKey])
      }, new RegExp(`^RangeError: ${messages.EC_PUBLIC_KEY_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('public key is invalid (version is 0x01)', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        publicKey[0] = 0x01
        secp256k1.publicKey.combine([publicKey])
      }, new RegExp(`^Error: ${messages.EC_PUBLIC_KEY_PARSE_FAIL}$`))
      t.end()
    })

    t.test('compressed should be a boolean', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.publicKey.combine([publicKey], null)
      }, new RegExp(`^TypeError: ${messages.COMPRESSED_TYPE_INVALID}$`))
      t.end()
    })

    t.test('P + (-P) = 0', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey1 = util.getPublicKey(privateKey).compressed
        const publicKey2 = Buffer.from(publicKey1)
        publicKey2[0] = publicKey2[0] ^ 0x01
        secp256k1.publicKey.combine([publicKey1, publicKey2], true)
      }, new RegExp(`^Error: ${messages.EC_PUBLIC_KEY_COMBINE_FAIL}$`))
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const cnt = 1 + Math.floor(Math.random() * 3) // 1 <= cnt <= 3
        const privateKeys = []
        while (privateKeys.length < cnt) privateKeys.push(util.getPrivateKey())
        const publicKeys = privateKeys.map(function (privateKey) {
          return util.getPublicKey(privateKey).compressed
        })

        let expected = util.ec.g.mul(new BN(privateKeys[0]))
        for (let i = 1; i < privateKeys.length; ++i) {
          const publicPoint = util.ec.g.mul(new BN(privateKeys[i]))
          expected = expected.add(publicPoint)
        }

        const compressed = secp256k1.publicKey.combine(publicKeys, true)
        t.same(compressed.toString('hex'), expected.encode('hex', true))

        const uncompressed = secp256k1.publicKey.combine(publicKeys, false)
        t.same(uncompressed.toString('hex'), expected.encode('hex', false))

        t.end()
      })
    }

    t.end()
  })
}
