const util = require('./util')

module.exports = (t, secp256k1) => {
  t.test('ecdh', (t) => {
    t.test('public key should be an Uint8Array', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = null
        secp256k1.ecdh(publicKey, privateKey)
      }, /^Error: Expected public key to be an Uint8Array$/)
      t.end()
    })

    t.test('public key length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        secp256k1.ecdh(publicKey, privateKey)
      }, /^Error: Expected public key to be an Uint8Array with length \[33, 65]$/)
      t.end()
    })

    t.test('invalid public key', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        publicKey[0] = 0x00
        secp256k1.ecdh(publicKey, privateKey)
      }, /^Error: Public Key could not be parsed$/)
      t.end()
    })

    t.test('private key should be an Uint8Array', (t) => {
      t.throws(() => {
        const privateKey = null
        const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        secp256k1.ecdh(publicKey, privateKey)
      }, /^Error: Expected private key to be an Uint8Array$/)
      t.end()
    })

    t.test('private key invalid length', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey().slice(1)
        const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        secp256k1.ecdh(publicKey, privateKey)
      }, /^Error: Expected private key to be an Uint8Array with length 32$/)
      t.end()
    })

    t.test('private key equal zero', (t) => {
      t.throws(() => {
        const privateKey = util.ec.curve.zero.fromRed().toArrayLike(Buffer, 'be', 32)
        const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        secp256k1.ecdh(publicKey, privateKey)
      }, /^Error: Scalar was invalid \(zero or overflow\)$/)
      t.end()
    })

    t.test('secret key equal N', (t) => {
      t.throws(() => {
        const privateKey = util.ec.n.toArrayLike(Buffer, 'be', 32)
        const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        secp256k1.ecdh(publicKey, privateKey)
      }, /^Error: Scalar was invalid \(zero or overflow\)$/)
      t.end()
    })

    t.test('invalid output', (t) => {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(util.getPrivateKey()).compressed

      t.throws(() => {
        secp256k1.ecdh(publicKey, privateKey, null)
      }, /^Error: Expected output to be an Uint8Array$/)

      t.throws(() => {
        secp256k1.ecdh(publicKey, privateKey, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 32$/)

      t.end()
    })

    t.test('output as function', (t) => {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(util.getPrivateKey()).compressed

      t.plan(1)

      secp256k1.ecdh(publicKey, privateKey, (len) => {
        t.same(len, 32)
        return new Uint8Array(32)
      })

      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, (t) => {
      const privateKey1 = util.getPrivateKey()
      const publicKey1 = util.getPublicKey(privateKey1).compressed
      const privateKey2 = util.getPrivateKey()
      const publicKey2 = util.getPublicKey(privateKey2).compressed

      const shared1 = secp256k1.ecdh(publicKey1, privateKey2)
      const shared2 = secp256k1.ecdh(publicKey2, privateKey1)
      t.same(shared1, shared2)
    })

    t.end()
  })
}
