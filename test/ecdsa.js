import { randomBytes as getRandomBytes } from 'crypto'
import * as util from './util'

const messages = util.messages

export default function (t, secp256k1) {
  t.test('ecdsa.sign', (t) => {
    t.test('message should be a Buffer', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        secp256k1.ecdsa.sign(null, privateKey)
      }, new RegExp(`^TypeError: ${messages.MESSAGE_TYPE_INVALID}$`))
      t.end()
    })

    t.test('message invalid length', (t) => {
      t.throws(() => {
        const message = util.getMessage().slice(1)
        const privateKey = util.getPrivateKey()
        secp256k1.ecdsa.sign(message, privateKey)
      }, new RegExp(`^RangeError: ${messages.MESSAGE_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('private key should be a Buffer', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        secp256k1.ecdsa.sign(message, null)
      }, new RegExp(`^TypeError: ${messages.EC_PRIVATE_KEY_TYPE_INVALID}$`))
      t.end()
    })

    t.test('private key invalid length', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey().slice(1)
        secp256k1.ecdsa.sign(message, privateKey)
      }, new RegExp(`^RangeError: ${messages.EC_PRIVATE_KEY_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('noncefn should be a Function', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()
        secp256k1.ecdsa.sign(message, privateKey, null)
      }, new RegExp(`^TypeError: ${messages.NONCE_FUNCTION_TYPE_INVALID}$`))
      t.end()
    })

    t.test('noncefn return not a Buffer', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()
        const noncefn = () => null
        secp256k1.ecdsa.sign(message, privateKey, noncefn)
      }, new RegExp(`^Error: ${messages.ECDSA_SIGN_FAIL}$`))
      t.end()
    })

    t.test('noncefn return Buffer with invalid length', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()
        const noncefn = () => getRandomBytes(31)
        secp256k1.ecdsa.sign(message, privateKey, noncefn)
      }, new RegExp(`^Error: ${messages.ECDSA_SIGN_FAIL}$`))
      t.end()
    })

    t.test('check noncefn arguments', (t) => {
      t.plan(5)
      const message = util.getMessage()
      const privateKey = util.getPrivateKey()
      const noncedata = getRandomBytes(32)
      const noncefn = function (message2, privateKey2, algo, data2, attempt) {
        t.same(message2, message)
        t.same(privateKey, privateKey)
        t.same(algo, null)
        t.same(data2, noncedata)
        t.same(attempt, 0)
        return getRandomBytes(32)
      }
      secp256k1.ecdsa.sign(message, privateKey, noncefn, noncedata)
      t.end()
    })

    t.test('noncedata should be a Buffer', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()
        secp256k1.ecdsa.sign(message, privateKey, undefined, null)
      }, new RegExp(`^TypeError: ${messages.NONCE_DATA_TYPE_INVALID}$`))
      t.end()
    })

    t.test('noncedata length is invalid', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()
        const noncedata = getRandomBytes(31)
        secp256k1.ecdsa.sign(message, privateKey, undefined, noncedata)
      }, new RegExp(`^RangeError: ${messages.NONCE_DATA_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('private key is invalid', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.ec.n.toArrayLike(Buffer, 'be', 32)
        secp256k1.ecdsa.sign(message, privateKey)
      }, new RegExp(`^Error: ${messages.ECDSA_SIGN_FAIL}$`))
      t.end()
    })

    t.end()
  })

  t.test('ecdsa.verify', (t) => {
    t.test('signature should be a Buffer', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.ecdsa.verify(null, message, publicKey)
      }, new RegExp(`^TypeError: ${messages.ECDSA_SIGNATURE_TYPE_INVALID}$`))
      t.end()
    })

    t.test('signature length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey).slice(1)
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.ecdsa.verify(signature, message, publicKey)
      }, new RegExp(`^RangeError: ${messages.ECDSA_SIGNATURE_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('signature is invalid (r equal N)', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = Buffer.concat([
          util.ec.n.toArrayLike(Buffer, 'be', 32),
          getRandomBytes(32)
        ])
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.ecdsa.verify(signature, message, publicKey)
      }, new RegExp(`^Error: ${messages.ECDSA_SIGNATURE_PARSE_FAIL}$`))
      t.end()
    })

    t.test('message should be a Buffer', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.ecdsa.verify(signature, null, publicKey)
      }, new RegExp(`^TypeError: ${messages.MESSAGE_TYPE_INVALID}$`))
      t.end()
    })

    t.test('message length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.ecdsa.verify(signature, message.slice(1), publicKey)
      }, new RegExp(`^RangeError: ${messages.MESSAGE_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('public key should be a Buffer', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        secp256k1.ecdsa.verify(signature, message, null)
      }, new RegExp(`^TypeError: ${messages.EC_PUBLIC_KEY_TYPE_INVALID}$`))
      t.end()
    })

    t.test('public key length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        secp256k1.ecdsa.verify(signature, message, publicKey)
      }, new RegExp(`^RangeError: ${messages.EC_PUBLIC_KEY_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('public key is invalid (version is 0x01)', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        const publicKey = util.getPublicKey(privateKey).compressed
        publicKey[0] = 0x01
        secp256k1.ecdsa.verify(signature, message, publicKey)
      }, new RegExp(`^Error: ${messages.EC_PUBLIC_KEY_PARSE_FAIL}$`))
      t.end()
    })

    t.end()
  })

  t.test('ecdsa.recover', (t) => {
    t.test('signature should be a Buffer', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        secp256k1.ecdsa.recover(null, 0, message)
      }, new RegExp(`^TypeError: ${messages.ECDSA_SIGNATURE_TYPE_INVALID}$`))
      t.end()
    })

    t.test('signature length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey).slice(1)
        secp256k1.ecdsa.recover(signature, 0, message)
      }, new RegExp(`^RangeError: ${messages.ECDSA_SIGNATURE_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('signature is invalid (r equal N)', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const signature = Buffer.concat([
          util.ec.n.toArrayLike(Buffer, 'be', 32),
          getRandomBytes(32)
        ])
        secp256k1.ecdsa.recover(signature, 0, message)
      }, new RegExp(`^Error: ${messages.ECDSA_SIGNATURE_PARSE_FAIL}$`))
      t.end()
    })

    t.test('recovery should be a Number', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        secp256k1.ecdsa.recover(signature, null, message)
      }, new RegExp(`^TypeError: ${messages.ECDSA_RECOVERY_ID_TYPE_INVALID}$`))
      t.end()
    })

    t.test('recovery is invalid (equal 4)', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(privateKey, message)
        secp256k1.ecdsa.recover(signature, 4, message)
      }, new RegExp(`^RangeError: ${messages.ECDSA_RECOVERY_ID_VALUE_INVALID}$`.replace(/[\[\]]/g, '\\$&')))
      t.end()
    })

    t.test('message should be a Buffer', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        secp256k1.ecdsa.recover(signature, 0, null)
      }, new RegExp(`^TypeError: ${messages.MESSAGE_TYPE_INVALID}$`))
      t.end()
    })

    t.test('message length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage().slice(1)
        const signature = util.getSignature(message, privateKey)
        secp256k1.ecdsa.recover(signature, 0, message)
      }, new RegExp(`^RangeError: ${messages.MESSAGE_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('compressed should be a boolean', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        secp256k1.ecdsa.recover(signature, 0, message, null)
      }, new RegExp(`^TypeError: ${messages.COMPRESSED_TYPE_INVALID}$`))
      t.end()
    })

    t.end()
  })

  t.test('ecdsa.sign/ecdsa.verify/ecdsa.recover', (t) => {
    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey)
        const expected = util.sign(message, privateKey)

        const sigObj = secp256k1.ecdsa.sign(message, privateKey)
        t.same(sigObj.signature, expected.signatureLowS)
        t.same(sigObj.recovery, expected.recovery)

        const isValid = secp256k1.ecdsa.verify(sigObj.signature, message, publicKey.compressed)
        t.true(isValid)

        const compressed = secp256k1.ecdsa.recover(sigObj.signature, sigObj.recovery, message, true)
        t.same(compressed, publicKey.compressed)

        const uncompressed = secp256k1.ecdsa.recover(sigObj.signature, sigObj.recovery, message, false)
        t.same(uncompressed, publicKey.uncompressed)

        t.end()
      })
    }

    t.end()
  })
}
