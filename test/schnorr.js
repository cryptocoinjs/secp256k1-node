import { randomBytes as getRandomBytes } from 'crypto'
import * as util from './util'

const messages = util.messages

export default function (t, secp256k1) {
  t.test('schnorr.sign', (t) => {
    t.test('message should be a Buffer', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        secp256k1.schnorr.sign(null, privateKey)
      }, new RegExp(`^TypeError: ${messages.MESSAGE_TYPE_INVALID}$`))
      t.end()
    })

    t.test('message invalid length', (t) => {
      t.throws(() => {
        const message = util.getMessage().slice(1)
        const privateKey = util.getPrivateKey()
        secp256k1.schnorr.sign(message, privateKey)
      }, new RegExp(`^RangeError: ${messages.MESSAGE_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('private key should be a Buffer', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        secp256k1.schnorr.sign(message, null)
      }, new RegExp(`^TypeError: ${messages.EC_PRIVATE_KEY_TYPE_INVALID}$`))
      t.end()
    })

    t.test('private key invalid length', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey().slice(1)
        secp256k1.schnorr.sign(message, privateKey)
      }, new RegExp(`^RangeError: ${messages.EC_PRIVATE_KEY_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('noncefn should be a Function', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()
        secp256k1.schnorr.sign(message, privateKey, null)
      }, new RegExp(`^TypeError: ${messages.NONCE_FUNCTION_TYPE_INVALID}$`))
      t.end()
    })

    t.test('noncefn return not a Buffer', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()
        const noncefn = () => null
        secp256k1.schnorr.sign(message, privateKey, noncefn)
      }, new RegExp(`^Error: ${messages.SCHNORR_SIGN_FAIL}$`))
      t.end()
    })

    t.test('noncefn return Buffer with invalid length', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()
        const noncefn = () => getRandomBytes(31)
        secp256k1.schnorr.sign(message, privateKey, noncefn)
      }, new RegExp(`^Error: ${messages.SCHNORR_SIGN_FAIL}$`))
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
        t.same(algo, Buffer.from('5363686e6f72722b5348413235362020', 'hex'))
        t.same(data2, noncedata)
        t.same(attempt, 0)
        return getRandomBytes(32)
      }
      secp256k1.schnorr.sign(message, privateKey, noncefn, noncedata)
      t.end()
    })

    t.test('noncedata should be a Buffer', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()
        secp256k1.schnorr.sign(message, privateKey, undefined, null)
      }, new RegExp(`^TypeError: ${messages.NONCE_DATA_TYPE_INVALID}$`))
      t.end()
    })

    t.test('noncedata length is invalid', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()
        const noncedata = getRandomBytes(31)
        secp256k1.schnorr.sign(message, privateKey, undefined, noncedata)
      }, new RegExp(`^RangeError: ${messages.NONCE_DATA_LENGTH_INVALID}$`))
      t.end()
    })

    // Wait: https://github.com/bitcoin-core/secp256k1/pull/416
    // t.test('private key is invalid', (t) => {
    //   t.throws(() => {
    //     const message = util.getMessage()
    //     const privateKey = util.ec.n.toArrayLike(Buffer, 'be', 32)
    //     secp256k1.schnorr.sign(message, privateKey)
    //   }, new RegExp(`^Error: ${messages.SCHNORR_SIGN_FAIL}$`))
    //   t.end()
    // })

    t.end()
  })

  t.test('schnorr.verify', (t) => {
    t.test('signature should be a Buffer', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.schnorr.verify(null, message, publicKey)
      }, new RegExp(`^TypeError: ${messages.SCHNORR_SIGNATURE_TYPE_INVALID}$`))
      t.end()
    })

    t.test('signature length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey).slice(1)
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.schnorr.verify(signature, message, publicKey)
      }, new RegExp(`^RangeError: ${messages.SCHNORR_SIGNATURE_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('message should be a Buffer', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.schnorr.verify(signature, null, publicKey)
      }, new RegExp(`^TypeError: ${messages.MESSAGE_TYPE_INVALID}$`))
      t.end()
    })

    t.test('message length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage().slice(1)
        const signature = util.getSignature(message, privateKey)
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.schnorr.verify(signature, message, publicKey)
      }, new RegExp(`^RangeError: ${messages.MESSAGE_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('public key should be a Buffer', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        secp256k1.schnorr.verify(signature, message, null)
      }, new RegExp(`^TypeError: ${messages.EC_PUBLIC_KEY_TYPE_INVALID}$`))
      t.end()
    })

    t.test('public key length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        secp256k1.schnorr.verify(signature, message, publicKey)
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
        secp256k1.schnorr.verify(signature, message, publicKey)
      }, new RegExp(`^Error: ${messages.EC_PUBLIC_KEY_PARSE_FAIL}$`))
      t.end()
    })

    t.end()
  })

  t.test('schnorr.recover', (t) => {
    t.test('signature should be a Buffer', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        secp256k1.schnorr.recover(null, message)
      }, new RegExp(`^TypeError: ${messages.SCHNORR_SIGNATURE_TYPE_INVALID}$`))
      t.end()
    })

    t.test('signature length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey).slice(1)
        secp256k1.schnorr.recover(signature, message)
      }, new RegExp(`^RangeError: ${messages.SCHNORR_SIGNATURE_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('message should be a Buffer', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        secp256k1.schnorr.recover(signature, null)
      }, new RegExp(`^TypeError: ${messages.MESSAGE_TYPE_INVALID}$`))
      t.end()
    })

    t.test('message length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        secp256k1.schnorr.recover(signature, message.slice(1))
      }, new RegExp(`^RangeError: ${messages.MESSAGE_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('compressed should be a boolean', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        secp256k1.schnorr.recover(signature, message, null)
      }, new RegExp(`^TypeError: ${messages.COMPRESSED_TYPE_INVALID}$`))
      t.end()
    })

    t.end()
  })

  t.test('schnorr.generateNoncePair', (t) => {
    t.test('message should be a Buffer', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        secp256k1.schnorr.generateNoncePair(null, privateKey)
      }, new RegExp(`^TypeError: ${messages.MESSAGE_TYPE_INVALID}$`))
      t.end()
    })

    t.test('message invalid length', (t) => {
      t.throws(() => {
        const message = util.getMessage().slice(1)
        const privateKey = util.getPrivateKey()
        secp256k1.schnorr.generateNoncePair(message, privateKey)
      }, new RegExp(`^RangeError: ${messages.MESSAGE_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('private key should be a Buffer', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        secp256k1.schnorr.generateNoncePair(message, null)
      }, new RegExp(`^TypeError: ${messages.EC_PRIVATE_KEY_TYPE_INVALID}$`))
      t.end()
    })

    t.test('private key invalid length', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey().slice(1)
        secp256k1.schnorr.generateNoncePair(message, privateKey)
      }, new RegExp(`^RangeError: ${messages.EC_PRIVATE_KEY_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('noncefn should be a Function', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()
        secp256k1.schnorr.generateNoncePair(message, privateKey, null)
      }, new RegExp(`^TypeError: ${messages.NONCE_FUNCTION_TYPE_INVALID}$`))
      t.end()
    })

    t.test('noncefn return not a Buffer', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()
        const noncefn = () => null
        secp256k1.schnorr.generateNoncePair(message, privateKey, noncefn)
      }, new RegExp(`^Error: ${messages.SCHNORR_GENERATE_NONCE_PAIR_FAIL}$`))
      t.end()
    })

    t.test('noncefn return Buffer with invalid length', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()
        const noncefn = () => getRandomBytes(31)
        secp256k1.schnorr.generateNoncePair(message, privateKey, noncefn)
      }, new RegExp(`^Error: ${messages.SCHNORR_GENERATE_NONCE_PAIR_FAIL}$`))
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
        t.same(algo, Buffer.from('5363686e6f72722b5348413235362020', 'hex'))
        t.same(data2, noncedata)
        t.same(attempt, 0)
        return getRandomBytes(32)
      }
      secp256k1.schnorr.generateNoncePair(message, privateKey, noncefn, noncedata)
      t.end()
    })

    t.test('noncedata should be a Buffer', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()
        secp256k1.schnorr.generateNoncePair(message, privateKey, undefined, null)
      }, new RegExp(`^TypeError: ${messages.NONCE_DATA_TYPE_INVALID}$`))
      t.end()
    })

    t.test('noncedata length is invalid', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()
        const noncedata = getRandomBytes(31)
        secp256k1.schnorr.generateNoncePair(message, privateKey, undefined, noncedata)
      }, new RegExp(`^RangeError: ${messages.NONCE_DATA_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('compressed should be a boolean', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()
        secp256k1.schnorr.generateNoncePair(message, privateKey, undefined, undefined, null)
      }, new RegExp(`^TypeError: ${messages.COMPRESSED_TYPE_INVALID}$`))
      t.end()
    })

    t.end()
  })

  t.test('schnorr.partialSign', (t) => {
    t.test('message should be a Buffer', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        secp256k1.schnorr.partialSign(null, privateKey)
      }, new RegExp(`^TypeError: ${messages.MESSAGE_TYPE_INVALID}$`))
      t.end()
    })

    t.test('message invalid length', (t) => {
      t.throws(() => {
        const message = util.getMessage().slice(1)
        const privateKey = util.getPrivateKey()
        secp256k1.schnorr.partialSign(message, privateKey)
      }, new RegExp(`^RangeError: ${messages.MESSAGE_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('private key should be a Buffer', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        secp256k1.schnorr.partialSign(message, null)
      }, new RegExp(`^TypeError: ${messages.EC_PRIVATE_KEY_TYPE_INVALID}$`))
      t.end()
    })

    t.test('private key invalid length', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey().slice(1)
        secp256k1.schnorr.partialSign(message, privateKey)
      }, new RegExp(`^RangeError: ${messages.EC_PRIVATE_KEY_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('pubnonce should be a Buffer', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()
        secp256k1.schnorr.partialSign(message, privateKey, null)
      }, new RegExp(`^TypeError: ${messages.EC_PUBLIC_KEY_TYPE_INVALID}$`))
      t.end()
    })

    t.test('pubnonce length is invalid', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()
        const pubnonce = util.getPublicKey(privateKey).compressed.slice(1)
        secp256k1.schnorr.partialSign(message, privateKey, pubnonce)
      }, new RegExp(`^RangeError: ${messages.EC_PUBLIC_KEY_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('pubnonce is invalid (version is 0x01)', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()
        const pubnonce = util.getPublicKey(privateKey).compressed
        pubnonce[0] = 0x01
        secp256k1.schnorr.partialSign(message, privateKey, pubnonce)
      }, new RegExp(`^Error: ${messages.EC_PUBLIC_KEY_PARSE_FAIL}$`))
      t.end()
    })

    t.test('privnonce should be a Buffer', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()
        const pubnonce = util.getPublicKey(privateKey).compressed
        secp256k1.schnorr.partialSign(message, privateKey, pubnonce, null)
      }, new RegExp(`^TypeError: ${messages.EC_PRIVATE_KEY_TYPE_INVALID}$`))
      t.end()
    })

    t.test('privnonce invalid length', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()
        const pubnonce = util.getPublicKey(privateKey).compressed
        const privnonce = util.getPrivateKey().slice(1)
        secp256k1.schnorr.partialSign(message, privateKey, pubnonce, privnonce)
      }, new RegExp(`^RangeError: ${messages.EC_PRIVATE_KEY_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('privnonce is zero', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()
        const pubnonce = util.getPublicKey(privateKey).compressed
        const privnonce = util.BN_ZERO.toArrayLike(Buffer, 'be', 32)
        secp256k1.schnorr.partialSign(message, privateKey, pubnonce, privnonce)
      }, new RegExp(`^Error: ${messages.SCHNORR_PARTIAL_SIGN_FAIL}$`))
      t.end()
    })

    t.end()
  })

  t.test('schnorr.partialCombine', (t) => {
    t.test('signatures should be an Array', (t) => {
      t.throws(() => {
        secp256k1.schnorr.partialCombine(null)
      }, new RegExp(`^TypeError: ${messages.SCHNORR_SIGNATURES_TYPE_INVALID}$`))
      t.end()
    })

    t.test('signatures should have length greater that zero', (t) => {
      t.throws(() => {
        secp256k1.schnorr.partialCombine([])
      }, new RegExp(`^RangeError: ${messages.SCHNORR_SIGNATURES_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('signature should be a Buffer', (t) => {
      t.throws(() => {
        secp256k1.schnorr.partialCombine([ null ])
      }, new RegExp(`^TypeError: ${messages.SCHNORR_SIGNATURE_TYPE_INVALID}$`))
      t.end()
    })

    t.test('signature length invalid', (t) => {
      t.throws(() => {
        secp256k1.schnorr.partialCombine([ getRandomBytes(63) ])
      }, new RegExp(`^RangeError: ${messages.SCHNORR_SIGNATURE_LENGTH_INVALID}$`))
      t.end()
    })

    t.test('invalid signature', (t) => {
      const signature = Buffer.concat([
        getRandomBytes(32),
        util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
      ])
      t.throws(() => {
        secp256k1.schnorr.partialCombine([ signature ])
      }, new RegExp(`^Error: ${messages.SCHNORR_PARTIAL_COMBINE_FAIL}$`))
      t.end()
    })

    t.end()
  })

  t.test('schnorr.sign/schnorr.verify/schnorr.recover', (t) => {
    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey)

        const signature = secp256k1.schnorr.sign(message, privateKey)

        const isValid = secp256k1.schnorr.verify(signature, message, publicKey.compressed)
        t.true(isValid)

        const compressed = secp256k1.schnorr.recover(signature, message, true)
        t.same(compressed, publicKey.compressed)

        const uncompressed = secp256k1.schnorr.recover(signature, message, false)
        t.same(uncompressed, publicKey.uncompressed)

        t.end()
      })
    }

    t.end()
  })

  t.test('schnorr.generateNoncePair/schnorr.partialSign/schnorr.partialCombine/schnorr.verify', (t) => {
    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const message = util.getMessage()
        const data = Array.apply(null, Array(3)).map(() => {
          const privateKey = util.getPrivateKey()
          return {
            privateKey,
            publicKey: util.getPublicKey(privateKey).compressed,
            nonce: secp256k1.schnorr.generateNoncePair(message, privateKey)
          }
        })

        const partialSignatures = data.map((item, i) => {
          const pubnonces = data.filter((_, j) => i !== j).map((item) => item.nonce.pubnonce)
          const pubnonceOthers = secp256k1.publicKey.combine(pubnonces)
          return secp256k1.schnorr.partialSign(message, item.privateKey, pubnonceOthers, item.nonce.privnonce)
        })

        const signature = secp256k1.schnorr.partialCombine(partialSignatures)
        const publicKey = secp256k1.publicKey.combine(data.map((item) => item.publicKey))
        t.true(secp256k1.schnorr.verify(signature, message, publicKey))

        t.end()
      })
    }

    t.end()
  })
}
