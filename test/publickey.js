const util = require('./util')

module.exports = (t, secp256k1) => {
  t.test('publicKeyVerify', (t) => {
    t.test('arg: invalid public key', (t) => {
      t.throws(() => {
        secp256k1.publicKeyVerify(null)
      }, /^Error: Expected public key to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        secp256k1.publicKeyVerify(publicKey)
      }, /^Error: Expected public key to be an Uint8Array with length \[33, 65]$/, 'should have length 33 or 65')

      t.end()
    })

    t.test('validate invalid public keys', (t) => {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey)

      const invalidVersion = Buffer.from(publicKey.compressed)
      invalidVersion[0] = 0x00
      t.false(secp256k1.publicKeyVerify(invalidVersion), 'invalid version byte')

      const invalidY = Buffer.from(publicKey.uncompressed)
      invalidY[64] ^= 0x01
      t.false(secp256k1.publicKeyVerify(invalidY), 'invalid Y')

      const invalidLength = Buffer.from(publicKey.uncompressed)
      invalidLength[0] = publicKey.compressed[0]
      t.false(secp256k1.publicKeyVerify(invalidLength), 'invalid length')

      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, (t) => {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey)
      t.true(secp256k1.publicKeyVerify(publicKey.compressed), 'should be a valid public key')
      t.true(secp256k1.publicKeyVerify(publicKey.uncompressed), 'should be a valid public key')
    })

    t.end()
  })

  t.test('publicKeyCreate', (t) => {
    t.test('arg: invalid private key', (t) => {
      t.throws(() => {
        secp256k1.publicKeyCreate(null)
      }, /^Error: Expected private key to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey().slice(1)
        secp256k1.publicKeyCreate(privateKey)
      }, /^Error: Expected private key to be an Uint8Array with length 32$/, 'should have length 32')

      t.throws(() => {
        const privateKey = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
        secp256k1.publicKeyCreate(privateKey)
      }, /^Error: Private Key is invalid$/, 'should throw error on private key equal to N')

      t.throws(() => {
        const privateKey = util.BN_ZERO.toArrayLike(Buffer, 'be', 32)
        secp256k1.publicKeyCreate(privateKey)
      }, /^Error: Private Key is invalid$/, 'should throw error on private key equal to 0')

      t.end()
    })

    t.test('arg: invalid compressed flag', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        secp256k1.publicKeyCreate(privateKey, null)
      }, /^Error: Expected compressed to be a Boolean$/, 'should be a Boolean')

      t.end()
    })

    t.test('arg: invalid output', (t) => {
      const privateKey = util.getPrivateKey()

      t.throws(() => {
        secp256k1.publicKeyCreate(privateKey, true, null)
      }, /^Error: Expected output to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        secp256k1.publicKeyCreate(privateKey, true, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 33$/, 'should have length 33 if compressed')

      t.throws(() => {
        secp256k1.publicKeyCreate(privateKey, false, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 65$/, 'should have length 65 if uncompressed')

      secp256k1.publicKeyCreate(privateKey, true, (len) => {
        t.same(len, 33, 'compressed form should ask Uint8Array with length 33')
        return new Uint8Array(len)
      })

      secp256k1.publicKeyCreate(privateKey, false, (len) => {
        t.same(len, 65, 'uncompressed form should ask Uint8Array with length 65')
        return new Uint8Array(len)
      })

      t.plan(5)
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
    t.test('arg: invalid public key', (t) => {
      t.throws(() => {
        secp256k1.publicKeyConvert(null)
      }, /^Error: Expected public key to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        secp256k1.publicKeyConvert(publicKey)
      }, /^Error: Expected public key to be an Uint8Array with length \[33, 65]$/, 'should have length 33 or 65')

      t.throws(() => {
        const publicKey = new Uint8Array(33)
        secp256k1.publicKeyConvert(publicKey)
      }, /^Error: Public Key could not be parsed$/, 'should throw for invalid public key')

      t.end()
    })

    t.test('arg: invalid compressed flag', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.publicKeyConvert(publicKey, null)
      }, /^Error: Expected compressed to be a Boolean$/, 'should be a Boolean')

      t.end()
    })

    t.test('arg: invalid output', (t) => {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed

      t.throws(() => {
        secp256k1.publicKeyConvert(publicKey, true, null)
      }, /^Error: Expected output to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        secp256k1.publicKeyConvert(publicKey, true, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 33$/, 'should have length 33 if compressed')

      t.throws(() => {
        secp256k1.publicKeyConvert(publicKey, false, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 65$/, 'should have length 65 if uncompressed')

      secp256k1.publicKeyConvert(publicKey, true, (len) => {
        t.same(len, 33, 'compressed form should ask Uint8Array with length 33')
        return new Uint8Array(len)
      })

      secp256k1.publicKeyConvert(publicKey, false, (len) => {
        t.same(len, 65, 'uncompressed form should ask Uint8Array with length 65')
        return new Uint8Array(len)
      })

      t.plan(5)
      t.end()
    })

    t.test('special tests for cover loadPublicKey', (t) => {
      const p = util.ec.curve.p.toArray('be', 32)
      const one = util.BN_ONE.toArray('be', 32)

      t.throws(() => {
        const publicKey = Buffer.from([0x02, ...p])
        secp256k1.publicKeyConvert(publicKey)
      }, /^Error: Public Key could not be parsed$/, 'overflowed compressed key')

      t.throws(() => {
        const publicKey = Buffer.from([0x04, ...p, ...one])
        secp256k1.publicKeyConvert(publicKey)
      }, /^Error: Public Key could not be parsed$/, 'overflowed uncompressed key (x part)')

      t.throws(() => {
        const publicKey = Buffer.from([0x04, ...one, ...p])
        secp256k1.publicKeyConvert(publicKey)
      }, /^Error: Public Key could not be parsed$/, 'overflowed uncompressed key (y part)')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const keys = util.getPublicKey(privateKey)

        const publicKey = keys.uncompressed
        publicKey[0] = keys.point.y.isEven() ? 0x07 : 0x06

        secp256k1.publicKeyConvert(publicKey)
      }, /^Error: Public Key could not be parsed$/, 'odd flag for 0x06/0x07')

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
    t.test('arg: invalid public key', (t) => {
      t.throws(() => {
        secp256k1.publicKeyNegate(null)
      }, /^Error: Expected public key to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        secp256k1.publicKeyNegate(publicKey)
      }, /^Error: Expected public key to be an Uint8Array with length \[33, 65]$/, 'should have length 33 or 65')

      t.throws(() => {
        const publicKey = new Uint8Array(33)
        secp256k1.publicKeyNegate(publicKey)
      }, /^Error: Public Key could not be parsed$/, 'should throw for invalid public key')

      t.end()
    })

    t.test('arg: invalid compressed flag', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.publicKeyNegate(publicKey, null)
      }, /^Error: Expected compressed to be a Boolean$/, 'should be a boolean')
      t.end()
    })

    t.test('arg: invalid output', (t) => {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed

      t.throws(() => {
        secp256k1.publicKeyNegate(publicKey, true, null)
      }, /^Error: Expected output to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        secp256k1.publicKeyNegate(publicKey, true, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 33$/, 'should have length 33 if compressed')

      t.throws(() => {
        secp256k1.publicKeyNegate(publicKey, false, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 65$/, 'should have length 65 if uncompressed')

      secp256k1.publicKeyNegate(publicKey, true, (len) => {
        t.same(len, 33, 'compressed form should ask Uint8Array with length 33')
        return new Uint8Array(len)
      })

      secp256k1.publicKeyNegate(publicKey, false, (len) => {
        t.same(len, 65, 'uncompressed form should ask Uint8Array with length 65')
        return new Uint8Array(len)
      })

      t.plan(5)
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, (t) => {
      const privateKey = util.getPrivateKey()
      const expected = util.getPublicKey(privateKey)

      expected.point.y = expected.point.y.redNeg()

      const compressed = secp256k1.publicKeyNegate(expected.uncompressed, true, Buffer.alloc)
      t.same(compressed, Buffer.from(expected.point.encode(null, true)))

      const uncompressed = secp256k1.publicKeyNegate(expected.compressed, false, Buffer.alloc)
      t.same(uncompressed, Buffer.from(expected.point.encode(null, false)))
    })

    t.end()
  })

  t.test('publicKeyCombine', (t) => {
    t.test('arg: invalid public keys', (t) => {
      t.throws(() => {
        secp256k1.publicKeyCombine(null)
      }, /^Error: Expected public keys to be an Array$/, 'should be an Array')

      t.throws(() => {
        secp256k1.publicKeyCombine([])
      }, /^Error: Expected public keys array will have more than zero items$/, 'array should have at least 1 item')

      t.throws(() => {
        secp256k1.publicKeyCombine([null])
      }, /^Error: Expected public key to be an Uint8Array$/, 'public key should be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        secp256k1.publicKeyCombine([publicKey])
      }, /^Error: Expected public key to be an Uint8Array with length \[33, 65]$/, 'public key should have length 33 or 65')

      t.throws(() => {
        const publicKey = new Uint8Array(33)
        secp256k1.publicKeyCombine([publicKey])
      }, /^Error: Public Key could not be parsed$/, 'should throw for invalid public key')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey1 = util.getPublicKey(privateKey).compressed
        const publicKey2 = Buffer.from(publicKey1)
        publicKey2[0] = publicKey2[0] ^ 0x01
        secp256k1.publicKeyCombine([publicKey1, publicKey2], true)
      }, /^Error: The sum of the public keys is not valid$/, 'should throw on invalid result: P + (-P) = 0')

      t.end()
    })

    t.test('arg: invalid compressed flag', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.publicKeyCombine([publicKey], null)
      }, /^Error: Expected compressed to be a Boolean$/, 'should be a boolean')

      t.end()
    })

    t.test('arg: invalid output', (t) => {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed

      t.throws(() => {
        secp256k1.publicKeyCombine([publicKey], true, null)
      }, /^Error: Expected output to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        secp256k1.publicKeyCombine([publicKey], true, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 33$/, 'should have length 33 if compressed')

      t.throws(() => {
        secp256k1.publicKeyCombine([publicKey], false, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 65$/, 'should have length 65 if uncompressed')

      secp256k1.publicKeyCombine([publicKey], true, (len) => {
        t.same(len, 33, 'compressed form should ask Uint8Array with length 33')
        return new Uint8Array(len)
      })

      secp256k1.publicKeyCombine([publicKey], false, (len) => {
        t.same(len, 65, 'uncompressed form should ask Uint8Array with length 65')
        return new Uint8Array(len)
      })

      t.plan(5)
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, (t) => {
      const cnt = 1 + util.getPrivateKey()[0] % 3 // 1 <= cnt <= 3
      const privateKeys = []
      while (privateKeys.length < cnt) privateKeys.push(util.getPrivateKey())
      const publicKeys = privateKeys.map((privateKey) => util.getPublicKey(privateKey).compressed)

      let expected = util.ec.g.mul(new util.BN(privateKeys[0]))
      for (let i = 1; i < privateKeys.length; ++i) {
        const publicPoint = util.ec.g.mul(new util.BN(privateKeys[i]))
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
    t.test('arg: invalid public key', (t) => {
      t.throws(() => {
        const tweak = util.getTweak()
        secp256k1.publicKeyTweakAdd(null, tweak)
      }, /^Error: Expected public key to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        const tweak = util.getTweak()
        secp256k1.publicKeyTweakAdd(publicKey, tweak)
      }, /^Error: Expected public key to be an Uint8Array with length \[33, 65]$/, 'should have length 33 or 65')

      t.throws(() => {
        const publicKey = new Uint8Array(33)
        const tweak = util.getTweak()
        secp256k1.publicKeyTweakAdd(publicKey, tweak)
      }, /^Error: Public Key could not be parsed$/, 'should throws for invalid public key')

      t.end()
    })

    t.test('arg: invalid tweak', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.publicKeyTweakAdd(publicKey, null)
      }, /^Error: Expected tweak to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        const tweak = util.getTweak().slice(1)
        secp256k1.publicKeyTweakAdd(publicKey, tweak)
      }, /^Error: Expected tweak to be an Uint8Array with length 32$/, 'should have length 32')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        const tweak = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
        secp256k1.publicKeyTweakAdd(publicKey, tweak)
      }, /^Error: The tweak was out of range or the resulted private key is invalid$/, 'should throw for overflowed tweak')

      t.throws(() => {
        const publicKey = Buffer.from(util.ec.g.encode(null, true))
        publicKey[0] = publicKey[0] ^ 0x01 // change sign of G
        const tweak = util.BN_ONE.toArrayLike(Buffer, 'be', 32)
        secp256k1.publicKeyTweakAdd(publicKey, tweak, true)
      }, /^Error: The tweak was out of range or the resulted private key is invalid$/, 'should throw on invalid result: G * 1 - G = 0')

      t.end()
    })

    t.test('arg: invalid compressed flag', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        const tweak = util.getTweak()
        secp256k1.publicKeyTweakAdd(publicKey, tweak, null)
      }, /^Error: Expected compressed to be a Boolean$/, 'should be a boolean')
      t.end()
    })

    t.test('arg: invalid output', (t) => {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed
      const tweak = util.getTweak()

      t.throws(() => {
        secp256k1.publicKeyTweakAdd(publicKey, tweak, true, null)
      }, /^Error: Expected output to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        secp256k1.publicKeyTweakAdd(publicKey, tweak, true, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 33$/, 'should have length 33 if compressed')

      t.throws(() => {
        secp256k1.publicKeyTweakAdd(publicKey, tweak, false, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 65$/, 'should have length 65 if uncompressed')

      secp256k1.publicKeyTweakAdd(publicKey, tweak, true, (len) => {
        t.same(len, 33, 'compressed form should ask Uint8Array with length 33')
        return new Uint8Array(len)
      })

      secp256k1.publicKeyTweakAdd(publicKey, tweak, false, (len) => {
        t.same(len, 65, 'uncompressed form should ask Uint8Array with length 65')
        return new Uint8Array(len)
      })

      t.plan(5)
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, (t) => {
      const privateKey = util.getPrivateKey()
      const tweak = util.getTweak()

      const publicPoint = util.ec.g.mul(new util.BN(privateKey))
      const publicKey = Buffer.from(publicPoint.encode(null, true))
      const expected = util.ec.g.mul(new util.BN(tweak)).add(publicPoint)

      const compressed = secp256k1.publicKeyTweakAdd(publicKey, tweak, true, Buffer.alloc)
      t.same(compressed.toString('hex'), expected.encode('hex', true))

      const uncompressed = secp256k1.publicKeyTweakAdd(publicKey, tweak, false, Buffer.alloc)
      t.same(uncompressed.toString('hex'), expected.encode('hex', false))
    })

    t.end()
  })

  t.test('publicKeyTweakMul', (t) => {
    t.test('arg: invalid public key', (t) => {
      t.throws(() => {
        const tweak = util.getTweak()
        secp256k1.publicKeyTweakMul(null, tweak)
      }, /^Error: Expected public key to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        const tweak = util.getTweak()
        secp256k1.publicKeyTweakMul(publicKey, tweak)
      }, /^Error: Expected public key to be an Uint8Array with length \[33, 65]$/, 'should have length 33 or 65')

      t.throws(() => {
        const publicKey = new Uint8Array(33)
        const tweak = util.getTweak()
        secp256k1.publicKeyTweakMul(publicKey, tweak)
      }, /^Error: Public Key could not be parsed$/, 'should throws for invalid public key')

      t.end()
    })

    t.test('arg: invalid tweak', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.publicKeyTweakMul(publicKey, null)
      }, /^Error: Expected tweak to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        const tweak = util.getTweak().slice(1)
        secp256k1.publicKeyTweakMul(publicKey, tweak)
      }, /^Error: Expected tweak to be an Uint8Array with length 32$/, 'should have length 32')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        const tweak = util.ec.curve.n.toArrayLike(Buffer, 'be', 32)
        secp256k1.publicKeyTweakMul(publicKey, tweak)
      }, /^Error: The tweak was out of range or equal to zero$/, 'should throw for overflowed tweak')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        const tweak = util.BN_ZERO.toArrayLike(Buffer, 'be', 32)
        secp256k1.publicKeyTweakMul(publicKey, tweak)
      }, /^Error: The tweak was out of range or equal to zero$/, 'should throw for zero tweak')

      t.end()
    })

    t.test('arg: invalid compressed flag', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        const tweak = util.getTweak()
        secp256k1.publicKeyTweakMul(publicKey, tweak, null)
      }, /^Error: Expected compressed to be a Boolean$/, 'should be a boolean')
      t.end()
    })

    t.test('arg: invalid output', (t) => {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed
      const tweak = util.getTweak()

      t.throws(() => {
        secp256k1.publicKeyTweakMul(publicKey, tweak, true, null)
      }, /^Error: Expected output to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        secp256k1.publicKeyTweakMul(publicKey, tweak, true, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 33$/, 'should have length 33 if compressed')

      t.throws(() => {
        secp256k1.publicKeyTweakMul(publicKey, tweak, false, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 65$/, 'should have length 65 if uncompressed')

      secp256k1.publicKeyTweakMul(publicKey, tweak, true, (len) => {
        t.same(len, 33, 'compressed form should ask Uint8Array with length 33')
        return new Uint8Array(len)
      })

      secp256k1.publicKeyTweakMul(publicKey, tweak, false, (len) => {
        t.same(len, 65, 'uncompressed form should ask Uint8Array with length 65')
        return new Uint8Array(len)
      })

      t.plan(5)
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, (t) => {
      const privateKey = util.getPrivateKey()
      const publicPoint = util.ec.g.mul(new util.BN(privateKey))
      const publicKey = Buffer.from(publicPoint.encode(null, true))
      const tweak = util.getTweak()

      if (new util.BN(tweak).cmp(util.BN_ZERO) === 0) {
        t.throws(() => {
          secp256k1.publicKeyTweakMul(publicKey, tweak)
        }, /^Error: The tweak was out of range or equal to zero$/)
      } else {
        const expected = publicPoint.mul(tweak)

        const compressed = secp256k1.publicKeyTweakMul(publicKey, tweak, true, Buffer.alloc)
        t.same(compressed.toString('hex'), expected.encode('hex', true))

        const uncompressed = secp256k1.publicKeyTweakMul(publicKey, tweak, false, Buffer.alloc)
        t.same(uncompressed.toString('hex'), expected.encode('hex', false))
      }
    })
  })
}
