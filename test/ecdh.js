const util = require('./util')

module.exports = (t, secp256k1) => {
  t.test('ecdh', (t) => {
    t.test('arg: invalid public key', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = null
        secp256k1.ecdh(publicKey, privateKey)
      }, /^Error: Expected public key to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        secp256k1.ecdh(publicKey, privateKey)
      }, /^Error: Expected public key to be an Uint8Array with length \[33, 65]$/, 'should have length 33 or 65')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        publicKey[0] = 0x01
        secp256k1.ecdh(publicKey, privateKey)
      }, /^Error: Public Key could not be parsed$/, 'should throw on invalid public key: version 0x01')
      t.end()
    })

    t.test('arg: invalid private key', (t) => {
      t.throws(() => {
        const privateKey = null
        const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        secp256k1.ecdh(publicKey, privateKey)
      }, /^Error: Expected private key to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey().slice(1)
        const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        secp256k1.ecdh(publicKey, privateKey)
      }, /^Error: Expected private key to be an Uint8Array with length 32$/, 'should have length 32')

      t.throws(() => {
        const privateKey = util.ec.n.toArrayLike(Buffer, 'be', 32)
        const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        secp256k1.ecdh(publicKey, privateKey)
      }, /^Error: Scalar was invalid \(zero or overflow\)$/, 'should throw for overflowed private key')

      t.throws(() => {
        const privateKey = util.ec.curve.zero.fromRed().toArrayLike(Buffer, 'be', 32)
        const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        secp256k1.ecdh(publicKey, privateKey)
      }, /^Error: Scalar was invalid \(zero or overflow\)$/, 'should throw for zero private key')

      t.end()
    })

    t.test('arg: invalid output', (t) => {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed

      t.throws(() => {
        secp256k1.ecdh(publicKey, privateKey, null)
      }, /^Error: Expected output to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        secp256k1.ecdh(publicKey, privateKey, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 32$/, 'should have length 32')

      secp256k1.ecdh(publicKey, privateKey, (len) => {
        t.same(len, 32, 'compressed form should ask Uint8Array with length 32')
        return new Uint8Array(len)
      })

      t.plan(3)
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
