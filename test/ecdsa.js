const util = require('./util')

module.exports = (t, secp256k1) => {
  t.test('ecdsaSign', (t) => {
    t.test('arg: invalid message', (t) => {
      t.throws(() => {
        secp256k1.ecdsaSign(null)
      }, /^Error: Expected message to be an Uint8Array$/, 'should be be an Uint8Array')

      t.throws(() => {
        const message = util.getMessage().slice(1)
        secp256k1.ecdsaSign(message)
      }, /^Error: Expected message to be an Uint8Array with length 32$/, 'should have length 32')

      t.end()
    })

    t.test('arg: invalid private key', (t) => {
      t.throws(() => {
        const message = util.getMessage()
        secp256k1.ecdsaSign(message, null)
      }, /^Error: Expected private key to be an Uint8Array$/, 'should be be an Uint8Array')

      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey().slice(1)
        secp256k1.ecdsaSign(message, privateKey)
      }, /^Error: Expected private key to be an Uint8Array with length 32$/, 'should have length 32')

      t.throws(() => {
        const message = util.getMessage()
        const privateKey = new Uint8Array(32)
        secp256k1.ecdsaSign(message, privateKey)
      }, /^Error: The nonce generation function failed, or the private key was invalid$/, 'should throw on zero private key')

      t.throws(() => {
        const message = util.getMessage()
        const privateKey = util.ec.n.toArrayLike(Buffer, 'be', 32)
        secp256k1.ecdsaSign(message, privateKey)
      }, /^Error: The nonce generation function failed, or the private key was invalid$/, 'should throw on overflowed private key: equal to N')

      t.end()
    })

    t.test('arg: invalid options', (t) => {
      const message = util.getMessage()
      const privateKey = util.getPrivateKey()

      t.throws(() => {
        secp256k1.ecdsaSign(message, privateKey, null)
      }, /^Error: Expected options to be an Object$/, 'should be an Object')

      t.throws(() => {
        secp256k1.ecdsaSign(message, privateKey, Number(42))
      }, /^Error: Expected options to be an Object$/, 'should be an Object')

      t.throws(() => {
        secp256k1.ecdsaSign(message, privateKey, { data: null })
      }, /^Error: Expected options.data to be an Uint8Array$/, 'data should be an Uint8Array')

      t.throws(() => {
        secp256k1.ecdsaSign(message, privateKey, { noncefn: null })
      }, /^Error: Expected options.noncefn to be a Function$/, 'noncefn should be a Function')

      t.end()
    })

    t.test('arg: invalid output', (t) => {
      const message = util.getMessage()
      const privateKey = util.getPrivateKey()

      t.throws(() => {
        secp256k1.ecdsaSign(message, privateKey, {}, null)
      }, /^Error: Expected output to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        secp256k1.ecdsaSign(message, privateKey, {}, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 64$/, 'should have length 64')

      secp256k1.ecdsaSign(message, privateKey, {}, (len) => {
        t.same(len, 64, 'should ask Uint8Array with length 64')
        return new Uint8Array(len)
      })

      t.plan(3)
      t.end()
    })

    t.test('noncefn usage', (t) => {
      const message = util.getMessage()
      const privateKey = util.getPrivateKey()
      const data = util.getMessage()

      t.test('noncefn call', (t) => {
        function noncefn () {
          t.same(arguments.length, 5)
          t.same(arguments[0], message)
          t.same(arguments[1], privateKey)
          t.same(arguments[2], null)
          t.same(arguments[3], data)
          t.same(arguments[4], 0)
          return util.getMessage()
        }
        secp256k1.ecdsaSign(message, privateKey, { data, noncefn })

        t.plan(6)
        t.end()
      })

      t.test('invalid nonce', (t) => {
        t.throws(() => {
          secp256k1.ecdsaSign(message, privateKey, { noncefn: () => null })
        }, /^Error: The nonce generation function failed, or the private key was invalid$/, 'nonce should be an Uint8Array')

        t.throws(() => {
          secp256k1.ecdsaSign(message, privateKey, { noncefn: () => Number(42) })
        }, /^Error: The nonce generation function failed, or the private key was invalid$/, 'nonce should be an Uint8Array')

        t.throws(() => {
          secp256k1.ecdsaSign(message, privateKey, { noncefn: () => new Uint8Array(42) })
        }, /^Error: The nonce generation function failed, or the private key was invalid$/, 'nonce should be an Uint8Array')

        t.end()
      })

      t.end()
    })

    t.end()
  })

  t.test('ecdsaVerify', (t) => {
    t.test('arg: invalid signature', (t) => {
      t.throws(() => {
        secp256k1.ecdsaVerify(null)
      }, /^Error: Expected signature to be an Uint8Array$/, 'should be be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey).slice(1)
        secp256k1.ecdsaVerify(signature)
      }, /^Error: Expected signature to be an Uint8Array with length 64$/, 'should have length 64')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = Buffer.concat([
          util.ec.n.toArrayLike(Buffer, 'be', 32),
          util.getMessage()
        ])
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.ecdsaVerify(signature, message, publicKey)
      }, /^Error: Signature could not be parsed$/, 'should throw for invalid signature: r equal to N')

      t.end()
    })

    t.test('arg: invalid message', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.ecdsaVerify(signature, null, publicKey)
      }, /^Error: Expected message to be an Uint8Array$/, 'should be be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        const publicKey = util.getPublicKey(privateKey).compressed
        secp256k1.ecdsaVerify(signature, message.slice(1), publicKey)
      }, /^Error: Expected message to be an Uint8Array with length 32$/, 'should have length 32')

      t.end()
    })

    t.test('arg: invalid public key', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        secp256k1.ecdsaVerify(signature, message, null)
      }, /^Error: Expected public key to be an Uint8Array$/, 'should be be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        secp256k1.ecdsaVerify(signature, message, publicKey)
      }, /^Error: Expected public key to be an Uint8Array with length \[33, 65]$/, 'should have length 33 or 65')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        const publicKey = util.getPublicKey(privateKey).compressed
        publicKey[0] = 0x01
        secp256k1.ecdsaVerify(signature, message, publicKey)
      }, /^Error: Public Key could not be parsed$/, 'should throw on invalid public key: version is 0x01')

      t.end()
    })

    t.test('return true/false', (t) => {
      const message = util.getMessage()
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey)
      const sigObj = util.sign(message, privateKey)

      t.true(secp256k1.ecdsaVerify(sigObj.signatureLowS, message, publicKey.compressed), 'true for valid data')

      const newMessage = Buffer.from([message[0] ^ 0x01, ...message.slice(1)])
      t.false(secp256k1.ecdsaVerify(sigObj.signatureLowS, newMessage, publicKey.compressed), 'false for new message')

      const newSignatureR = Buffer.concat([Buffer.alloc(32, 0), sigObj.signatureLowS.slice(32, 64)])
      t.false(secp256k1.ecdsaVerify(newSignatureR, message, publicKey.compressed), 'false for invalid signature (zero r)')

      const newSignatureS = Buffer.concat([sigObj.signatureLowS.slice(0, 32), Buffer.alloc(32, 0)])
      t.false(secp256k1.ecdsaVerify(newSignatureS, message, publicKey.compressed), 'false for invalid signature (zero s)')

      t.end()
    })

    t.end()
  })

  t.test('ecdsaRecover', (t) => {
    t.test('arg: invalid signature', (t) => {
      t.throws(() => {
        secp256k1.ecdsaRecover(null)
      }, /^Error: Expected signature to be an Uint8Array$/, 'should be be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey).slice(1)
        secp256k1.ecdsaRecover(signature, 0, message)
      }, /^Error: Expected signature to be an Uint8Array with length 64$/, 'should have length 64')

      t.throws(() => {
        const message = util.getMessage()
        const signature = Buffer.concat([
          util.ec.n.toArrayLike(Buffer, 'be', 32),
          util.getMessage()
        ])
        secp256k1.ecdsaRecover(signature, 0, message)
      }, /^Error: Signature could not be parsed$/, 'should throw on invalid signature: r equal to N')

      t.end()
    })

    t.test('arg: invalid recovery', (t) => {
      const privateKey = util.getPrivateKey()
      const message = util.getMessage()
      const sigObj = util.sign(message, privateKey)

      t.throws(() => {
        secp256k1.ecdsaRecover(sigObj.signature, null, message)
      }, /^Error: Expected recovery id to be a Number within interval \[0, 3]$/, 'should be a Number')

      t.throws(() => {
        secp256k1.ecdsaRecover(sigObj.signature, 4, message)
      }, /^Error: Expected recovery id to be a Number within interval \[0, 3]$/, 'should throw for recovery outside interval')

      t.end()
    })

    t.test('arg: invalid message', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        secp256k1.ecdsaRecover(signature, 0, null)
      }, /^Error: Expected message to be an Uint8Array$/, 'should be be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage().slice(1)
        const signature = util.getSignature(message, privateKey)
        secp256k1.ecdsaRecover(signature, 0, message)
      }, /^Error: Expected message to be an Uint8Array with length 32$/, 'should have length 32')

      t.end()
    })

    t.test('arg: invalid compressed flag', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey)
        secp256k1.ecdsaRecover(signature, 0, message, null)
      }, /^Error: Expected compressed to be a Boolean$/, 'should be a boolean')
      t.end()
    })

    t.test('arg: invalid output', (t) => {
      const privateKey = util.getPrivateKey()
      const message = util.getMessage()
      const sig = util.sign(message, privateKey)

      t.throws(() => {
        secp256k1.ecdsaRecover(sig.signature, sig.recid, message, true, null)
      }, /^Error: Expected output to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        secp256k1.ecdsaRecover(sig.signature, sig.recid, message, true, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 33$/, 'should have length 33 if compressed')

      t.throws(() => {
        secp256k1.ecdsaRecover(sig.signature, sig.recid, message, false, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 65$/, 'should have length 65 if uncompressed')

      secp256k1.ecdsaRecover(sig.signature, sig.recid, message, true, (len) => {
        t.same(len, 33, 'compressed form should ask Uint8Array with length 33')
        return new Uint8Array(len)
      })

      secp256k1.ecdsaRecover(sig.signature, sig.recid, message, false, (len) => {
        t.same(len, 65, 'uncompressed form should ask Uint8Array with length 65')
        return new Uint8Array(len)
      })

      t.plan(5)
      t.end()
    })

    t.test('can not be recovered', (t) => {
      const privateKey = util.getPrivateKey()
      const message = util.getMessage()
      const sigObj = util.sign(message, privateKey)

      t.throws(() => {
        const newSignatureR = Buffer.concat([Buffer.alloc(32, 0), sigObj.signatureLowS.slice(32, 64)])
        secp256k1.ecdsaRecover(newSignatureR, sigObj.recid, message)
      }, /^Error: Public key could not be recover$/, 'invalid signature (zero r)')

      t.throws(() => {
        const newSignatureS = Buffer.concat([sigObj.signatureLowS.slice(0, 32), Buffer.alloc(32, 0)])
        secp256k1.ecdsaRecover(newSignatureS, sigObj.recid, message)
      }, /^Error: Public key could not be recover$/, 'invalid signature (zero s)')

      t.throws(() => {
        secp256k1.ecdsaRecover(sigObj.signature, sigObj.recid ^ 0x02, message)
      }, /^Error: Public key could not be recover$/, 'invalid recovery id')

      t.end()
    })

    t.end()
  })

  t.test('ecdsaSign/ecdsaVerify/ecdsaRecover', (t) => {
    util.repeat(t, 'random tests', util.env.repeat, (t) => {
      const message = util.getMessage()
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey)
      const expected = util.sign(message, privateKey)

      const sigObj = secp256k1.ecdsaSign(message, privateKey, {}, Buffer.alloc)
      t.same(sigObj.signature, expected.signatureLowS)
      t.same(sigObj.recid, expected.recid)

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
