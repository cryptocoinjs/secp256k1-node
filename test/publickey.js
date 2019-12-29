const BN = require('bn.js')
const util = require('./util')

module.exports = (t, secp256k1) => {
  t.test('publicKeyCreate', (t) => {
    t.test('private key should be an Uint8Array', (t) => {
      t.throws(() => {
        secp256k1.publicKeyCreate(null)
      }, /^Error: Expected private key to be an Uint8Array$/)
      t.end()
    })

    t.test('invalid private key length', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey().slice(1)
        secp256k1.publicKeyCreate(privateKey)
      }, /^Error: Expected private key to be an Uint8Array with length 32$/)
      t.end()
    })

    t.test('compressed should be a boolean', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        secp256k1.publicKeyCreate(privateKey, null)
      }, /^Error: Expected compressed to be a Boolean$/)
      t.end()
    })

    t.test('invalid output', (t) => {
      const privateKey = util.getPrivateKey()

      t.throws(() => {
        secp256k1.publicKeyCreate(privateKey, true, null)
      }, /^Error: Expected output to be an Uint8Array$/)

      t.throws(() => {
        secp256k1.publicKeyCreate(privateKey, true, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 33$/)

      t.throws(() => {
        secp256k1.publicKeyCreate(privateKey, false, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 65$/)

      t.end()
    })

    t.test('overflow', (t) => {
      t.throws(() => {
        const privateKey = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
        secp256k1.publicKeyCreate(privateKey)
      }, /^Error: Private Key is invalid$/)
      t.end()
    })

    t.test('equal zero', (t) => {
      t.throws(() => {
        const privateKey = util.BN_ZERO.toArrayLike(Buffer, 'be', 32)
        secp256k1.publicKeyCreate(privateKey)
      }, /^Error: Private Key is invalid$/)
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, (t) => {
      const privateKey = util.getPrivateKey()
      const expected = util.getPublicKey(privateKey)

      const compressed = secp256k1.publicKeyCreate(privateKey, true, Buffer.alloc)
      t.same(compressed, expected.compressed)

      const uncompressed = secp256k1.publicKeyCreate(privateKey, false, Buffer.alloc)
      t.same(uncompressed, expected.uncompressed)
    })

    t.end()
  })

  t.test('publicKeyConvert', (t) => {
    t.test('public key should be an Uint8Array', (t) => {
      t.throws(() => {
        secp256k1.publicKeyConvert(null)
      }, /^Error: Expected public key to be an Uint8Array$/)
      t.end()
    })

    t.test('invalid public key length', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        secp256k1.publicKeyConvert(publicKey)
      }, /^Error: Expected public key to be an Uint8Array with length \[33, 65]$/)
      t.end()
    })

    t.test('compressed should be a boolean', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.publicKeyConvert(publicKey, null)
      }, /^Error: Expected compressed to be a Boolean$/)
      t.end()
    })

    t.test('with invalid output', (t) => {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed

      t.throws(() => {
        secp256k1.publicKeyConvert(publicKey, true, null)
      }, /^Error: Expected output to be an Uint8Array$/)

      t.throws(() => {
        secp256k1.publicKeyConvert(publicKey, true, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 33$/)

      t.throws(() => {
        secp256k1.publicKeyConvert(publicKey, false, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 65$/)

      t.end()
    })

    t.test('with output as function', (t) => {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed

      t.plan(2)

      secp256k1.publicKeyConvert(publicKey, true, (len) => {
        t.same(len, 33)
        return new Uint8Array(33)
      })

      secp256k1.publicKeyConvert(publicKey, false, (len) => {
        t.same(len, 65)
        return new Uint8Array(65)
      })

      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, (t) => {
      const privateKey = util.getPrivateKey()
      const expected = util.getPublicKey(privateKey)

      const compressed = secp256k1.publicKeyConvert(expected.uncompressed, true, Buffer.alloc)
      t.same(compressed, expected.compressed)

      const uncompressed = secp256k1.publicKeyConvert(expected.compressed, false, Buffer.alloc)
      t.same(uncompressed, expected.uncompressed)
    })

    t.end()
  })

  t.test('publicKeyNegate', (t) => {
    t.test('public key should be an Uint8Array', (t) => {
      t.throws(() => {
        secp256k1.publicKeyNegate(null)
      }, /^Error: Expected public key to be an Uint8Array$/)
      t.end()
    })

    t.test('invalid public key length', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        secp256k1.publicKeyNegate(publicKey)
      }, /^Error: Expected public key to be an Uint8Array with length \[33, 65]$/)
      t.end()
    })

    t.test('compressed should be a boolean', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.publicKeyNegate(publicKey, null)
      }, /^Error: Expected compressed to be a Boolean$/)
      t.end()
    })

    t.test('with invalid output', (t) => {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed

      t.throws(() => {
        secp256k1.publicKeyNegate(publicKey, true, null)
      }, /^Error: Expected output to be an Uint8Array$/)

      t.throws(() => {
        secp256k1.publicKeyNegate(publicKey, true, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 33$/)

      t.throws(() => {
        secp256k1.publicKeyNegate(publicKey, false, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 65$/)

      t.end()
    })

    t.test('with output as function', (t) => {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed

      t.plan(2)

      secp256k1.publicKeyNegate(publicKey, true, (len) => {
        t.same(len, 33)
        return new Uint8Array(33)
      })

      secp256k1.publicKeyNegate(publicKey, false, (len) => {
        t.same(len, 65)
        return new Uint8Array(65)
      })

      t.end()
    })

    // TODO
    // util.repeat(t, 'random tests', util.env.repeat, (t) => {
    //   const privateKey = util.getPrivateKey()
    //   const expected = util.getPublicKey(privateKey)

    //   const compressed = secp256k1.publicKeyNegate(expected.uncompressed, true, Buffer.alloc)
    //   t.same(compressed, expected.compressed)

    //   const uncompressed = secp256k1.publicKeyNegate(expected.compressed, false, Buffer.alloc)
    //   t.same(uncompressed, expected.uncompressed)
    // })

    t.end()
  })

  t.test('publicKeyCombine', (t) => {
    t.test('public keys should be an Array', (t) => {
      t.throws(() => {
        secp256k1.publicKeyCombine(null)
      }, /^Error: Expected public keys to be an Array$/)
      t.end()
    })

    t.test('public keys should have length greater that zero', (t) => {
      t.throws(() => {
        secp256k1.publicKeyCombine([])
      }, /^Error: Expected public keys array will have more than zero items$/)
      t.end()
    })

    t.test('public key should be an Uint8Array', (t) => {
      t.throws(() => {
        secp256k1.publicKeyCombine([null])
      }, /^Error: Expected public key to be an Uint8Array$/)
      t.end()
    })

    t.test('public key length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        secp256k1.publicKeyCombine([publicKey])
      }, /^Error: Expected public key to be an Uint8Array with length \[33, 65]$/)
      t.end()
    })

    t.test('public key is invalid (version is 0x01)', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        publicKey[0] = 0x01
        secp256k1.publicKeyCombine([publicKey])
      }, /^Error: Public Key could not be parsed$/)
      t.end()
    })

    t.test('compressed should be a boolean', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.publicKeyCombine([publicKey], null)
      }, /^Error: Expected compressed to be a Boolean$/)
      t.end()
    })

    t.test('publicKeyCombine with output as function', (t) => {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed

      t.plan(2)

      secp256k1.publicKeyCombine([publicKey], true, (len) => {
        t.same(len, 33)
        return new Uint8Array(33)
      })

      secp256k1.publicKeyCombine([publicKey], false, (len) => {
        t.same(len, 65)
        return new Uint8Array(65)
      })

      t.end()
    })

    t.test('P + (-P) = 0', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey1 = util.getPublicKey(privateKey).compressed
        const publicKey2 = Buffer.from(publicKey1)
        publicKey2[0] = publicKey2[0] ^ 0x01
        secp256k1.publicKeyCombine([publicKey1, publicKey2], true)
      }, /^Error: The sum of the public keys is not valid$/)
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, (t) => {
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

      const compressed = secp256k1.publicKeyCombine(publicKeys, true, Buffer.alloc)
      t.same(compressed.toString('hex'), expected.encode('hex', true))

      const uncompressed = secp256k1.publicKeyCombine(publicKeys, false, Buffer.alloc)
      t.same(uncompressed.toString('hex'), expected.encode('hex', false))
    })

    t.end()
  })

  t.test('publicKeyTweakAdd', (t) => {
    t.test('public key should be an Uint8Array', (t) => {
      t.throws(() => {
        const tweak = util.getTweak()
        secp256k1.publicKeyTweakAdd(null, tweak)
      }, /^Error: Expected public key to be an Uint8Array$/)
      t.end()
    })

    t.test('public key length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        const tweak = util.getTweak()
        secp256k1.publicKeyTweakAdd(publicKey, tweak)
      }, /^Error: Expected public key to be an Uint8Array with length \[33, 65]$/)
      t.end()
    })

    t.test('public key is invalid (version is 0x01)', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        publicKey[0] = 0x01
        const tweak = util.getTweak()
        secp256k1.publicKeyTweakAdd(publicKey, tweak)
      }, /^Error: Public Key could not be parsed$/)
      t.end()
    })

    t.test('tweak should be an Uint8Array', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.publicKeyTweakAdd(publicKey, null)
      }, /^Error: Expected tweak to be an Uint8Array$/)
      t.end()
    })

    t.test('tweak length length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        const tweak = util.getTweak().slice(1)
        secp256k1.publicKeyTweakAdd(publicKey, tweak)
      }, /^Error: Expected tweak to be an Uint8Array with length 32$/)
      t.end()
    })

    t.test('tweak overflow', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        const tweak = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
        secp256k1.publicKeyTweakAdd(publicKey, tweak)
      }, /^Error: The tweak was out of range or the resulted private key is invalid$/)
      t.end()
    })

    t.test('tweak produce infinity point', (t) => {
      // G * 1 - G = 0
      t.throws(() => {
        const publicKey = Buffer.from(util.ec.g.encode(null, true))
        publicKey[0] = publicKey[0] ^ 0x01 // change sign of G
        const tweak = util.BN_ONE.toArrayLike(Buffer, 'be', 32)
        secp256k1.publicKeyTweakAdd(publicKey, tweak, true)
      }, /^Error: The tweak was out of range or the resulted private key is invalid$/)
      t.end()
    })

    t.test('compressed should be a boolean', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        const tweak = util.getTweak()
        secp256k1.publicKeyTweakAdd(publicKey, tweak, null)
      }, /^Error: Expected compressed to be a Boolean$/)
      t.end()
    })

    t.test('publicKeyTweakAdd with invalid output', (t) => {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed
      const tweak = util.getTweak()

      t.throws(() => {
        secp256k1.publicKeyTweakAdd(publicKey, tweak, true, null)
      }, /^Error: Expected output to be an Uint8Array$/)

      t.throws(() => {
        secp256k1.publicKeyTweakAdd(publicKey, tweak, true, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 33$/)

      t.throws(() => {
        secp256k1.publicKeyTweakAdd(publicKey, tweak, false, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 65$/)

      t.end()
    })

    t.test('publicKeyTweakAdd with output as function', (t) => {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed
      const tweak = util.getTweak()

      t.plan(2)

      secp256k1.publicKeyTweakAdd(publicKey, tweak, true, (len) => {
        t.same(len, 33)
        return new Uint8Array(33)
      })

      secp256k1.publicKeyTweakAdd(publicKey, tweak, false, (len) => {
        t.same(len, 65)
        return new Uint8Array(65)
      })

      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, (t) => {
      const privateKey = util.getPrivateKey()
      const tweak = util.getTweak()

      const publicPoint = util.ec.g.mul(new BN(privateKey))
      const publicKey = Buffer.from(publicPoint.encode(null, true))
      const expected = util.ec.g.mul(new BN(tweak)).add(publicPoint)

      const compressed = secp256k1.publicKeyTweakAdd(publicKey, tweak, true, Buffer.alloc)
      t.same(compressed.toString('hex'), expected.encode('hex', true))

      const uncompressed = secp256k1.publicKeyTweakAdd(publicKey, tweak, false, Buffer.alloc)
      t.same(uncompressed.toString('hex'), expected.encode('hex', false))
    })

    t.end()
  })

  t.test('publicKeyTweakMul', (t) => {
    t.test('public key should be an Uint8Array', (t) => {
      t.throws(() => {
        const tweak = util.getTweak()
        secp256k1.publicKeyTweakMul(null, tweak)
      }, /^Error: Expected public key to be an Uint8Array$/)
      t.end()
    })

    t.test('public key length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        const tweak = util.getTweak()
        secp256k1.publicKeyTweakMul(publicKey, tweak)
      }, /^Error: Expected public key to be an Uint8Array with length \[33, 65]$/)
      t.end()
    })

    t.test('public key is invalid (version is 0x01)', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        publicKey[0] = 0x01
        const tweak = util.getTweak()
        secp256k1.publicKeyTweakMul(publicKey, tweak)
      }, /^Error: Public Key could not be parsed$/)
      t.end()
    })

    t.test('tweak should be an Uint8Array', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.publicKeyTweakMul(publicKey, null)
      }, /^Error: Expected tweak to be an Uint8Array$/)
      t.end()
    })

    t.test('tweak length is invalid', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        const tweak = util.getTweak().slice(1)
        secp256k1.publicKeyTweakMul(publicKey, tweak)
      }, /^Error: Expected tweak to be an Uint8Array with length 32$/)
      t.end()
    })

    // t.test('tweak is zero', (t) => {
    //   // t.throws(() => {
    //     const privateKey = util.getPrivateKey()
    //     const publicKey = util.getPublicKey(privateKey).compressed
    //     const tweak = util.BN_ZERO.toArrayLike(Buffer, 'be', 32)
    //     secp256k1.publicKeyTweakMul(publicKey, tweak)
    //     console.log(secp256k1.publicKeyTweakMul(publicKey, tweak))
    //   // }, /^Error: Expected tweak to be an Uint8Array with length 32$/)
    //   t.end()
    // })

    t.test('tweak overflow', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        const tweak = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
        secp256k1.publicKeyTweakMul(publicKey, tweak)
      }, /^Error: The tweak was out of range or equal to zero$/)
      t.end()
    })

    t.test('compressed should be a boolean', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        const tweak = util.getTweak()
        secp256k1.publicKeyTweakMul(publicKey, tweak, null)
      }, /^Error: Expected compressed to be a Boolean$/)
      t.end()
    })

    t.test('invalid output', (t) => {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed
      const tweak = util.getTweak()

      t.throws(() => {
        secp256k1.publicKeyTweakMul(publicKey, tweak, true, null)
      }, /^Error: Expected output to be an Uint8Array$/)

      t.throws(() => {
        secp256k1.publicKeyTweakMul(publicKey, tweak, true, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 33$/)

      t.throws(() => {
        secp256k1.publicKeyTweakMul(publicKey, tweak, false, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 65$/)

      t.end()
    })

    t.test('output as function', (t) => {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed
      const tweak = util.getTweak()

      t.plan(2)

      secp256k1.publicKeyTweakMul(publicKey, tweak, true, (len) => {
        t.same(len, 33)
        return new Uint8Array(33)
      })

      secp256k1.publicKeyTweakMul(publicKey, tweak, false, (len) => {
        t.same(len, 65)
        return new Uint8Array(65)
      })

      t.end()
    })

    // TODO
    util.repeat(t, 'random tests', util.env.repeat, (t) => {
      const privateKey = util.getPrivateKey()
      const publicPoint = util.ec.g.mul(new BN(privateKey))
      const publicKey = Buffer.from(publicPoint.encode(null, true))
      const tweak = util.getTweak()

      if (new BN(tweak).cmp(util.BN_ZERO) === 0) {
        t.throws(() => {
          secp256k1.publicKeyTweakMul(publicKey, tweak)
        }, /^Error: The tweak was out of range or equal to zero$/)
      } else {
        // const expected = publicPoint.mul(tweak)

        // const compressed = secp256k1.publicKeyTweakMul(publicKey, tweak, true, Buffer.alloc)
        // t.same(compressed.toString('hex'), expected.encode('hex', true))

        // const uncompressed = secp256k1.publicKeyTweakMul(publicKey, tweak, false, Buffer.alloc)
        // t.same(uncompressed.toString('hex'), expected.encode('hex', false))
      }
    })
  })
}
