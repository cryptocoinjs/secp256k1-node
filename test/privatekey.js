import BN from 'bn.js'
import * as util from './util'

const messages = util.messages

export default function (t, secp256k1) {
  t.test('privateKey.verify', (t) => {
    t.test('should be a Buffer', (t) => {
      t.throws(() => {
        secp256k1.privateKey.verify(null)
      }, new RegExp(`^TypeError: ${messages.EC_PRIVATE_KEY_TYPE_INVALID}$`))
      t.end()
    })

    t.test('invalid length', (t) => {
      const privateKey = util.getPrivateKey().slice(1)
      t.false(secp256k1.privateKey.verify(privateKey))
      t.end()
    })

    t.test('zero key', (t) => {
      const privateKey = util.BN_ZERO.toArrayLike(Buffer, 'be', 32)
      t.false(secp256k1.privateKey.verify(privateKey))
      t.end()
    })

    t.test('equal to N', (t) => {
      const privateKey = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
      t.false(secp256k1.privateKey.verify(privateKey))
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const privateKey = util.getPrivateKey()
        t.true(secp256k1.privateKey.verify(privateKey))
        t.end()
      })
    }

    t.end()
  })

  t.test('privateKey.export', (t) => {
    t.test('private key should be a Buffer', (t) => {
      t.throws(() => {
        secp256k1.privateKey.export(null)
      }, new RegExp(`^TypeError: ${messages.EC_PRIVATE_KEY_TYPE_INVALID}$`))
      t.end()
    })

    t.test('private key length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey().slice(1)
        secp256k1.privateKey.export(privateKey)
      }, new RegExp(`^RangeError: ${messages.EC_PRIVATE_KEY_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('compressed should be a boolean', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        secp256k1.privateKey.export(privateKey, null)
      }, new RegExp(`^TypeError: ${messages.COMPRESSED_TYPE_INVALID}$`))
      t.end()
    })

    t.test('private key is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
        secp256k1.privateKey.export(privateKey)
      }, new RegExp(`^Error: ${messages.EC_PRIVATE_KEY_EXPORT_DER_FAIL}$`))
      t.end()
    })

    t.end()
  })

  t.test('privateKey.import', (t) => {
    t.test('should be a Buffer', (t) => {
      t.throws(() => {
        secp256k1.privateKey.import(null)
      }, new RegExp(`^TypeError: ${messages.EC_PRIVATE_KEY_TYPE_INVALID}$`))
      t.end()
    })

    t.test('invalid format', (t) => {
      t.throws(() => {
        const buffer = Buffer.from([ 0x00 ])
        secp256k1.privateKey.import(buffer)
      }, new RegExp(`^Error: ${messages.EC_PRIVATE_KEY_IMPORT_DER_FAIL}$`))
      t.end()
    })

    t.end()
  })

  t.test('privateKey.export/privateKey.import', (t) => {
    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const privateKey = util.getPrivateKey()

        const der1 = secp256k1.privateKey.export(privateKey, true)
        const privateKey1 = secp256k1.privateKey.import(der1)
        t.same(privateKey1, privateKey)

        const der2 = secp256k1.privateKey.export(privateKey, false)
        const privateKey2 = secp256k1.privateKey.import(der2)
        t.same(privateKey2, privateKey)

        t.end()
      })
    }

    t.end()
  })

  t.test('privateKey.tweakAdd', (t) => {
    t.test('private key should be a Buffer', (t) => {
      t.throws(() => {
        const tweak = util.getTweak()
        secp256k1.privateKey.tweakAdd(null, tweak)
      }, new RegExp(`^TypeError: ${messages.EC_PRIVATE_KEY_TYPE_INVALID}$`))
      t.end()
    })

    t.test('private key length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey().slice(1)
        const tweak = util.getTweak()
        secp256k1.privateKey.tweakAdd(privateKey, tweak)
      }, new RegExp(`^RangeError: ${messages.EC_PRIVATE_KEY_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('tweak should be a Buffer', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        secp256k1.privateKey.tweakAdd(privateKey, null)
      }, new RegExp(`^TypeError: ${messages.TWEAK_TYPE_INVALID}$`))
      t.end()
    })

    t.test('tweak length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const tweak = util.getTweak().slice(1)
        secp256k1.privateKey.tweakAdd(privateKey, tweak)
      }, new RegExp(`^RangeError: ${messages.TWEAK_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('result is zero: (N - 1) + 1', (t) => {
      t.throws(() => {
        const privateKey = util.ec.curve.n.sub(util.BN_ONE).toArrayLike(Buffer, 'be', 32)
        const tweak = util.BN_ONE.toArrayLike(Buffer, 'be', 32)
        secp256k1.privateKey.tweakAdd(privateKey, tweak)
      }, new RegExp(`^Error: ${messages.EC_PRIVATE_KEY_TWEAK_ADD_FAIL}$`))
      t.end()
    })

    t.test('tweak overflow', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const tweak = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
        secp256k1.privateKey.tweakAdd(privateKey, tweak)
      }, new RegExp(`^Error: ${messages.EC_PRIVATE_KEY_TWEAK_ADD_FAIL}$`))
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const privateKey = util.getPrivateKey()
        const tweak = util.getTweak()

        const expected = new BN(privateKey).add(new BN(tweak)).mod(util.ec.curve.n)
        if (expected.cmp(util.BN_ZERO) === 0) {
          t.throws(() => {
            secp256k1.privateKey.tweakAdd(privateKey, tweak)
          }, new RegExp(`^Error: ${messages.EC_PRIVATE_KEY_TWEAK_ADD_FAIL}$`))
        } else {
          const result = secp256k1.privateKey.tweakAdd(privateKey, tweak)
          t.same(result.toString('hex'), expected.toString(16, 64))
        }

        t.end()
      })
    }

    t.end()
  })

  t.test('privateKey.tweakMul', (t) => {
    t.test('private key should be a Buffer', (t) => {
      t.throws(() => {
        const tweak = util.getTweak()
        secp256k1.privateKey.tweakMul(null, tweak)
      }, new RegExp(`^TypeError: ${messages.EC_PRIVATE_KEY_TYPE_INVALID}$`))
      t.end()
    })

    t.test('private key length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey().slice(1)
        const tweak = util.getTweak()
        secp256k1.privateKey.tweakMul(privateKey, tweak)
      }, new RegExp(`^RangeError: ${messages.EC_PRIVATE_KEY_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('tweak should be a Buffer', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        secp256k1.privateKey.tweakMul(privateKey, null)
      }, new RegExp(`^TypeError: ${messages.TWEAK_TYPE_INVALID}$`))
      t.end()
    })

    t.test('tweak length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const tweak = util.getTweak().slice(1)
        secp256k1.privateKey.tweakMul(privateKey, tweak)
      }, new RegExp(`^RangeError: ${messages.TWEAK_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('tweak is 0', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const tweak = util.BN_ZERO.toArrayLike(Buffer, 'be', 32)
        secp256k1.privateKey.tweakMul(privateKey, tweak)
      }, new RegExp(`^Error: ${messages.EC_PRIVATE_KEY_TWEAK_MUL_FAIL}$`))
      t.end()
    })

    t.test('tweak equal N', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const tweak = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
        secp256k1.privateKey.tweakMul(privateKey, tweak)
      }, new RegExp(`^Error: ${messages.EC_PRIVATE_KEY_TWEAK_MUL_FAIL}$`))
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const privateKey = util.getPrivateKey()
        const tweak = util.getTweak()

        if (new BN(tweak).cmp(util.BN_ZERO) === 0) {
          t.throws(() => {
            secp256k1.privateKey.tweakMul(privateKey, tweak)
          }, new RegExp(`^Error: ${messages.EC_PRIVATE_KEY_TWEAK_MUL_FAIL}$`))
        } else {
          const expected = new BN(privateKey).mul(new BN(tweak)).mod(util.ec.curve.n)
          const result = secp256k1.privateKey.tweakMul(privateKey, tweak)
          t.same(result.toString('hex'), expected.toString(16, 64))
        }

        t.end()
      })
    }

    t.end()
  })
}
