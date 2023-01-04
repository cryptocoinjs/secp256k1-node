const util = require('./util')

const testVectors = [{
  pk: [
    0xD6, 0x9C, 0x35, 0x09, 0xBB, 0x99, 0xE4, 0x12,
    0xE6, 0x8B, 0x0F, 0xE8, 0x54, 0x4E, 0x72, 0x83,
    0x7D, 0xFA, 0x30, 0x74, 0x6D, 0x8B, 0xE2, 0xAA,
    0x65, 0x97, 0x5F, 0x29, 0xD2, 0x2D, 0xC7, 0xB9
  ],
  msg: [
    0x4D, 0xF3, 0xC3, 0xF6, 0x8F, 0xCC, 0x83, 0xB2,
    0x7E, 0x9D, 0x42, 0xC9, 0x04, 0x31, 0xA7, 0x24,
    0x99, 0xF1, 0x78, 0x75, 0xC8, 0x1A, 0x59, 0x9B,
    0x56, 0x6C, 0x98, 0x89, 0xB9, 0x69, 0x67, 0x03
  ],
  sig: [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x3B, 0x78, 0xCE, 0x56, 0x3F,
    0x89, 0xA0, 0xED, 0x94, 0x14, 0xF5, 0xAA, 0x28,
    0xAD, 0x0D, 0x96, 0xD6, 0x79, 0x5F, 0x9C, 0x63,
    0x76, 0xAF, 0xB1, 0x54, 0x8A, 0xF6, 0x03, 0xB3,
    0xEB, 0x45, 0xC9, 0xF8, 0x20, 0x7D, 0xEE, 0x10,
    0x60, 0xCB, 0x71, 0xC0, 0x4E, 0x80, 0xF5, 0x93,
    0x06, 0x0B, 0x07, 0xD2, 0x83, 0x08, 0xD7, 0xF4
  ]
}
]

module.exports = (t, secp256k1) => {
  t.test('schnorrSign', (t) => {
    t.test('arg: invalid message', (t) => {
      t.throws(() => {
        secp256k1.schnorrSign(null)
      }, /^Error: Expected message to be an Uint8Array$/, 'should be be an Uint8Array')

      t.throws(() => {
        const message = util.getMessage().slice(1)
        secp256k1.schnorrSign(message)
      }, /^Error: Expected message to be an Uint8Array with length 32$/, 'should have length 32')

      t.end()
    })

    t.test('arg: invalid private key', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        secp256k1.schnorrSign(message, null)
      }, /^Error: Expected private key to be an Uint8Array$/, 'should be be an Uint8Array')

      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey().slice(1)
        secp256k1.schnorrSign(message, privateKey)
      }, /^Error: Expected private key to be an Uint8Array with length 32$/, 'should have length 32')

      t.throws(() => {
        const message = util.getMessage()
        const privateKey = new Uint8Array(32)
        secp256k1.schnorrSign(message, privateKey)
      }, /^Error: The nonce generation function failed, or the private key was invalid$/, 'should throw on zero private key')

      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.ec.n.toArrayLike(Buffer, 'be', 32)
        secp256k1.schnorrSign(message, privateKey)
      }, /^Error: The nonce generation function failed, or the private key was invalid$/, 'should throw on overflowed private key: equal to N')

      t.end()
    })

    t.test('arg: invalid output', (t) => {
      const message = util.getMessage()
      const privateKey = util.getPrivateKey()

      t.throws(() => {
        secp256k1.schnorrSign(message, privateKey, null)
      }, /^Error: Expected output to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        secp256k1.schnorrSign(message, privateKey, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 64$/, 'should have length 64')

      secp256k1.schnorrSign(message, privateKey, (len) => {
        t.same(len, 64, 'should ask Uint8Array with length 64')
        return new Uint8Array(len)
      })

      t.plan(3)
      t.end()
    })

    t.test('should sign and verify', (t) => {
      const message = util.getMessage()
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed

      const { signature } = secp256k1.schnorrSign(message, privateKey, (len) => {
        return new Uint8Array(len)
      })

      const verified = secp256k1.schnorrVerify(signature, message, publicKey)
      t.same(verified, true, 'verify own signature')
      t.end()
    })

    t.test('should verify testvectors', (t) => {
      testVectors.forEach((tv) => {
        const publicKey = Buffer.from(tv.pk)
        const message = Buffer.from(tv.msg)
        const signature = Buffer.from(tv.sig)
        const verified = secp256k1.schnorrVerify(signature, message, publicKey)
        t.same(verified, true, 'verify own signature')
      })
      t.end()
    })

    t.end()
  })
}
