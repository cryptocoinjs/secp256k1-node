import * as util from './util'

const messages = util.messages

export default function (t, secp256k1) {
  function commonTests (t, ecdh) {
    t.test('public key should be a Buffer', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = null
        ecdh(publicKey, privateKey)
      }, new RegExp(`^TypeError: ${messages.EC_PUBLIC_KEY_TYPE_INVALID}$`))
      t.end()
    })

    t.test('public key length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        ecdh(publicKey, privateKey)
      }, new RegExp(`^RangeError: ${messages.EC_PUBLIC_KEY_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('invalid public key', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        publicKey[0] = 0x00
        ecdh(publicKey, privateKey)
      }, new RegExp(`^Error: ${messages.EC_PUBLIC_KEY_PARSE_FAIL}$`))
      t.end()
    })

    t.test('secret key should be a Buffer', (t) => {
      t.throws(() => {
        const privateKey = null
        const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        ecdh(publicKey, privateKey)
      }, new RegExp(`^TypeError: ${messages.EC_PRIVATE_KEY_TYPE_INVALID}$`))
      t.end()
    })

    t.test('secret key invalid length', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey().slice(1)
        const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        ecdh(publicKey, privateKey)
      }, new RegExp(`^RangeError: ${messages.EC_PRIVATE_KEY_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('secret key equal zero', (t) => {
      t.throws(() => {
        const privateKey = util.ec.curve.zero.fromRed().toArrayLike(Buffer, 'be', 32)
        const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        ecdh(publicKey, privateKey)
      }, new RegExp(`^Error: ${messages.ECDH_FAIL}$`.replace(/[()]/g, '\\$&')))
      t.end()
    })

    t.test('secret key equal N', (t) => {
      t.throws(() => {
        const privateKey = util.ec.n.toArrayLike(Buffer, 'be', 32)
        const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        ecdh(publicKey, privateKey)
      }, new RegExp(`^Error: ${messages.ECDH_FAIL}$`.replace(/[()]/g, '\\$&')))
      t.end()
    })
  }

  t.test('ecdh.sha256', (t) => {
    commonTests(t, secp256k1.ecdh.sha256)

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const privateKey1 = util.getPrivateKey()
        const publicKey1 = util.getPublicKey(privateKey1).compressed
        const privateKey2 = util.getPrivateKey()
        const publicKey2 = util.getPublicKey(privateKey2).compressed

        const shared1 = secp256k1.ecdh.sha256(publicKey1, privateKey2)
        const shared2 = secp256k1.ecdh.sha256(publicKey2, privateKey1)
        t.same(shared1, shared2)

        t.end()
      })
    }

    t.end()
  })

  t.test('ecdh.unsafe', (t) => {
    commonTests(t, secp256k1.ecdh.unsafe)

    t.test('compressed should be a boolean', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.ecdh.unsafe(publicKey, privateKey, null)
      }, new RegExp(`^TypeError: ${messages.COMPRESSED_TYPE_INVALID}$`))
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const privateKey1 = util.getPrivateKey()
        const publicKey1 = util.getPublicKey(privateKey1).compressed
        const privateKey2 = util.getPrivateKey()
        const publicKey2 = util.getPublicKey(privateKey2).compressed

        const shared1c = secp256k1.ecdh.unsafe(publicKey1, privateKey2, true)
        const shared2c = secp256k1.ecdh.unsafe(publicKey2, privateKey1, true)
        t.same(shared1c, shared2c)

        const shared1un = secp256k1.ecdh.unsafe(publicKey1, privateKey2, false)
        const shared2un = secp256k1.ecdh.unsafe(publicKey2, privateKey1, false)
        t.same(shared1un, shared2un)

        t.end()
      })
    }

    t.end()
  })
}
