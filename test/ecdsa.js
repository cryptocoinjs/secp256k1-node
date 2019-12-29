const { randomBytes } = require('crypto')
const util = require('./util')

module.exports = (t, secp256k1) => {
  t.test('sign', (t) => {
    t.test('message should be be an Uint8Array', (t) => {
      t.throws(() => {
        secp256k1.ecdsaSign(null)
      }, /^Error: Expected message to be an Uint8Array$/)
      t.end()
    })

    t.test('message invalid length', (t) => {
      t.throws(() => {
        const message = util.getMessage().slice(1)
        secp256k1.ecdsaSign(message)
      }, /^Error: Expected message to be an Uint8Array with length 32$/)
      t.end()
    })

    t.test('private key should be be an Uint8Array', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        secp256k1.ecdsaSign(message, null)
      }, /^Error: Expected private key to be an Uint8Array$/)
      t.end()
    })

    t.test('private key invalid length', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey().slice(1)
        secp256k1.ecdsaSign(message, privateKey)
      }, /^Error: Expected private key to be an Uint8Array with length 32$/)
      t.end()
    })

    t.test('private key is invalid', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.ec.n.toArrayLike(Buffer, 'be', 32)
        secp256k1.ecdsaSign(message, privateKey)
      }, /^Error: The nonce generation function failed, or the private key was invalid$/)
      t.end()
    })

    t.test('invalid output', (t) => {
      const message = util.getMessage()
      const privateKey = util.getPrivateKey()

      t.throws(() => {
        secp256k1.ecdsaSign(message, privateKey, null)
      }, /^Error: Expected output to be an Uint8Array$/)

      t.throws(() => {
        secp256k1.ecdsaSign(message, privateKey, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 64$/)

      t.end()
    })

    t.test('output as function', (t) => {
      const message = util.getMessage()
      const privateKey = util.getPrivateKey()

      t.plan(1)

      secp256k1.ecdsaSign(message, privateKey, (len) => {
        t.same(len, 64)
        return new Uint8Array(64)
      })

      t.end()
    })

    t.end()
  })

  t.test('verify', (t) => {
    t.test('signature should be be an Uint8Array', (t) => {
      t.throws(() => {
        secp256k1.ecdsaVerify(null)
      }, /^Error: Expected signature to be an Uint8Array$/)
      t.end()
    })

    t.test('signature length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey).slice(1)
        secp256k1.ecdsaVerify(signature)
      }, /^Error: Expected signature to be an Uint8Array with length 64$/)
      t.end()
    })

    t.test('signature is invalid (r equal N)', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = Buffer.concat([
          util.ec.n.toArrayLike(Buffer, 'be', 32),
          randomBytes(32)
        ])
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.ecdsaVerify(signature, message, publicKey)
      }, /^Error: Signature could not be parsed$/)
      t.end()
    })

    t.test('message should be be an Uint8Array', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.ecdsaVerify(signature, null, publicKey)
      }, /^Error: Expected message to be an Uint8Array$/)
      t.end()
    })

    t.test('message length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage().slice(1)
        const signature = util.getSignature(message, privateKey)
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.ecdsaVerify(signature, message, publicKey)
      }, /^Error: Expected message to be an Uint8Array with length 32$/)
      t.end()
    })

    t.test('public key should be be an Uint8Array', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        secp256k1.ecdsaVerify(signature, message, null)
      }, /^Error: Expected public key to be an Uint8Array$/)
      t.end()
    })

    t.test('public key length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        secp256k1.ecdsaVerify(signature, message, publicKey)
      }, /^Error: Expected public key to be an Uint8Array with length \[33, 65]$/)
      t.end()
    })

    t.test('public key is invalid (version is 0x01)', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        const publicKey = util.getPublicKey(privateKey).compressed
        publicKey[0] = 0x01
        secp256k1.ecdsaVerify(signature, message, publicKey)
      }, /^Error: Public Key could not be parsed$/)
      t.end()
    })

    t.end()
  })

  t.test('recover', (t) => {
    t.test('signature should be be an Uint8Array', (t) => {
      t.throws(() => {
        secp256k1.ecdsaRecover(null)
      }, /^Error: Expected signature to be an Uint8Array$/)
      t.end()
    })

    t.test('signature length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey).slice(1)
        secp256k1.ecdsaRecover(signature, 0, message)
      }, /^Error: Expected signature to be an Uint8Array with length 64$/)
      t.end()
    })

    t.test('signature is invalid (r equal N)', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const signature = Buffer.concat([
          util.ec.n.toArrayLike(Buffer, 'be', 32),
          randomBytes(32)
        ])
        secp256k1.ecdsaRecover(signature, 0, message)
      }, /^Error: Signature could not be parsed$/)
      t.end()
    })

    t.test('recovery should be a Number', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        secp256k1.ecdsaRecover(signature, null, message)
      }, /^Error: Expected recovery id to be a Number within interval \[0, 3]$/)
      t.end()
    })

    t.test('recovery is invalid (equal 4)', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(privateKey, message)
        secp256k1.ecdsaRecover(signature, 4, message)
      }, /^Error: Expected recovery id to be a Number within interval \[0, 3]$/)
      t.end()
    })

    t.test('message should be be an Uint8Array', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        secp256k1.ecdsaRecover(signature, 0, null)
      }, /^Error: Expected message to be an Uint8Array$/)
      t.end()
    })

    t.test('message length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage().slice(1)
        const signature = util.getSignature(message, privateKey)
        secp256k1.ecdsaRecover(signature, 0, message)
      }, /^Error: Expected message to be an Uint8Array with length 32$/)
      t.end()
    })

    t.test('compressed should be a boolean', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        secp256k1.ecdsaRecover(signature, 0, message, null)
      }, /^Error: Expected compressed to be a Boolean$/)
      t.end()
    })

    t.test('invalid output', (t) => {
      const privateKey = util.getPrivateKey()
      const message = util.getMessage()
      const signature = util.getSignature(message, privateKey)

      t.throws(() => {
        secp256k1.ecdsaRecover(signature, 0, message, undefined, null)
      }, /^Error: Expected output to be an Uint8Array$/)

      t.throws(() => {
        secp256k1.ecdsaRecover(signature, 0, message, true, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 33$/)

      t.throws(() => {
        secp256k1.ecdsaRecover(signature, 0, message, false, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 65$/)

      t.end()
    })

    t.test('output as function', (t) => {
      const privateKey = util.getPrivateKey()
      const message = util.getMessage()
      const { signature, recovery } = util.sign(message, privateKey)

      t.plan(2)

      secp256k1.ecdsaRecover(signature, recovery, message, true, (len) => {
        t.same(len, 33)
        return new Uint8Array(33)
      })

      secp256k1.ecdsaRecover(signature, recovery, message, false, (len) => {
        t.same(len, 65)
        return new Uint8Array(65)
      })

      t.end()
    })

    t.end()
  })

  t.test('sign/verify/recover', (t) => {
    util.repeat(t, 'random tests', util.env.repeat, (t) => {
      const message = util.getMessage()
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey)
      const expected = util.sign(message, privateKey)

      const sigObj = secp256k1.ecdsaSign(message, privateKey, Buffer.alloc)
      t.same(sigObj.ecdsaSignature, expected.ecdsaSignatureLowS)
      t.same(sigObj.ecdsaRecovery, expected.ecdsaRecovery)

      const isValid = secp256k1.ecdsaVerify(sigObj.signature, message, publicKey.compressed)
      t.true(isValid)

      const compressed = secp256k1.ecdsaRecover(sigObj.signature, sigObj.recid, message, true, Buffer.alloc)
      t.same(compressed, publicKey.compressed)

      const uncompressed = secp256k1.ecdsaRecover(sigObj.signature, sigObj.recid, message, false, Buffer.alloc)
      t.same(uncompressed, publicKey.uncompressed)
    })

    t.end()
  })
}
