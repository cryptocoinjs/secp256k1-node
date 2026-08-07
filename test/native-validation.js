const path = require('path')
const addon = require('node-gyp-build')(path.join(__dirname, '..'))

module.exports = (test) => {
  test('native fixed-length Uint8Array validation', (t) => {
    const secp256k1 = new addon.Secp256k1()

    const validPrivateKey = new Uint8Array(32)
    validPrivateKey[31] = 1

    const spoofLength = (realLength, fakeLength) => {
      const value = new Uint8Array(realLength)
      Object.defineProperty(value, 'length', {
        value: fakeLength,
        configurable: true
      })
      return value
    }

    t.test('fixed-length input', (t) => {
      t.equal(
        secp256k1.privateKeyVerify(validPrivateKey),
        0,
        'accepts an exact Uint8Array'
      )
      t.equal(
        secp256k1.privateKeyVerify(Buffer.from(validPrivateKey)),
        0,
        'accepts an exact Buffer'
      )
      t.throws(
        () => secp256k1.privateKeyVerify(new Uint8Array(33)),
        /^RangeError: private key must be a 32-byte Uint8Array$/,
        'rejects an oversized Uint8Array using its native byte length'
      )
      t.throws(
        () => secp256k1.privateKeyVerify(new Uint8ClampedArray(validPrivateKey)),
        /^TypeError: private key must be a 32-byte Uint8Array$/,
        'rejects another typed-array kind with the same byte length'
      )

      t.end()
    })

    t.test('fixed-length output', (t) => {
      const signature = Buffer.from('3006020101020101', 'hex')

      t.equal(
        secp256k1.signatureImport(new Uint8Array(64), signature),
        0,
        'accepts an exact Uint8Array'
      )
      t.equal(
        secp256k1.signatureImport(Buffer.alloc(64), signature),
        0,
        'accepts an exact Buffer'
      )
      t.throws(
        () => secp256k1.signatureImport(new Uint8Array(65), signature),
        /^RangeError: signature output must be a 64-byte Uint8Array$/,
        'rejects an oversized output using its native byte length'
      )
      t.throws(
        () => secp256k1.signatureImport(
          new Uint8ClampedArray(64),
          signature
        ),
        /^TypeError: signature output must be a 64-byte Uint8Array$/,
        'rejects another output typed-array kind with the same byte length'
      )

      // A 1-byte output masquerading as 64 bytes. Trusting `.length` here would
      // memcpy 64 bytes into a 1-byte buffer; the guard reads the native byte
      // length instead and rejects it before the write.
      const spoofedOutput = new Uint8Array(1)
      Object.defineProperty(spoofedOutput, 'length', { value: 64, configurable: true })
      t.throws(
        () => secp256k1.signatureImport(spoofedOutput, signature),
        /^RangeError: signature output must be a 64-byte Uint8Array$/,
        'rejects a spoofed-length output using its native byte length'
      )

      t.end()
    })

    t.test('in-place write (privateKeyNegate)', (t) => {
      t.equal(
        secp256k1.privateKeyNegate(new Uint8Array(validPrivateKey)),
        0,
        'accepts an exact Uint8Array'
      )
      t.equal(
        secp256k1.privateKeyNegate(Buffer.from(validPrivateKey)),
        0,
        'accepts an exact Buffer'
      )
      t.throws(
        () => secp256k1.privateKeyNegate(new Uint8Array(1)),
        /^RangeError: private key must be a 32-byte Uint8Array$/,
        'rejects an undersized buffer before the 32-byte in-place write'
      )

      t.end()
    })

    t.test('every fixed-length native argument checks its real byte length', (t) => {
      const message = new Uint8Array(32)
      const signature = new Uint8Array(64)
      const derSignature = Buffer.from('3006020101020101', 'hex')
      const publicKey = new Uint8Array(33)
      secp256k1.publicKeyCreate(publicKey, validPrivateKey)

      const bad32 = () => spoofLength(1, 32)
      const bad64 = () => spoofLength(1, 64)
      const bad72 = () => spoofLength(1, 72)

      const privateKeyError =
        /^RangeError: private key must be a 32-byte Uint8Array$/
      const tweakError =
        /^RangeError: tweak must be a 32-byte Uint8Array$/
      const signatureError =
        /^RangeError: signature must be a 64-byte Uint8Array$/
      const signatureOutput64Error =
        /^RangeError: signature output must be a 64-byte Uint8Array$/
      const signatureOutput72Error =
        /^RangeError: signature output must be a 72-byte Uint8Array$/
      const messageError =
        /^RangeError: message must be a 32-byte Uint8Array$/

      const rejectsSpoof = (name, expected, run) => {
        t.throws(run, expected, name)
      }
      const rawSign = (output, msg32, privateKey, data) => {
        return secp256k1.ecdsaSign(
          { signature: output, recid: null },
          msg32,
          privateKey,
          data,
          undefined
        )
      }
      const rawEcdh = (output, privateKey, hashfn, xbuf, ybuf) => {
        return secp256k1.ecdh(
          output,
          publicKey,
          privateKey,
          undefined,
          hashfn,
          xbuf,
          ybuf
        )
      }

      rejectsSpoof(
        'contextRandomize seed',
        /^RangeError: seed must be a 32-byte Uint8Array$/,
        () => secp256k1.contextRandomize(bad32())
      )
      rejectsSpoof(
        'privateKeyVerify private key',
        privateKeyError,
        () => secp256k1.privateKeyVerify(bad32())
      )
      rejectsSpoof(
        'privateKeyNegate private key',
        privateKeyError,
        () => secp256k1.privateKeyNegate(bad32())
      )
      rejectsSpoof(
        'privateKeyTweakAdd private key',
        privateKeyError,
        () => secp256k1.privateKeyTweakAdd(bad32(), validPrivateKey)
      )
      rejectsSpoof(
        'privateKeyTweakAdd tweak',
        tweakError,
        () => secp256k1.privateKeyTweakAdd(
          new Uint8Array(validPrivateKey),
          bad32()
        )
      )
      rejectsSpoof(
        'privateKeyTweakMul private key',
        privateKeyError,
        () => secp256k1.privateKeyTweakMul(bad32(), validPrivateKey)
      )
      rejectsSpoof(
        'privateKeyTweakMul tweak',
        tweakError,
        () => secp256k1.privateKeyTweakMul(
          new Uint8Array(validPrivateKey),
          bad32()
        )
      )
      rejectsSpoof(
        'publicKeyCreate private key',
        privateKeyError,
        () => secp256k1.publicKeyCreate(new Uint8Array(33), bad32())
      )
      rejectsSpoof(
        'publicKeyTweakAdd tweak',
        tweakError,
        () => secp256k1.publicKeyTweakAdd(
          new Uint8Array(33),
          publicKey,
          bad32()
        )
      )
      rejectsSpoof(
        'publicKeyTweakMul tweak',
        tweakError,
        () => secp256k1.publicKeyTweakMul(
          new Uint8Array(33),
          publicKey,
          bad32()
        )
      )
      rejectsSpoof(
        'signatureNormalize signature',
        signatureError,
        () => secp256k1.signatureNormalize(bad64())
      )
      rejectsSpoof(
        'signatureExport output',
        signatureOutput72Error,
        () => secp256k1.signatureExport(
          { output: bad72(), outputlen: 72 },
          signature
        )
      )
      rejectsSpoof(
        'signatureExport signature',
        signatureError,
        () => secp256k1.signatureExport(
          { output: new Uint8Array(72), outputlen: 72 },
          bad64()
        )
      )
      rejectsSpoof(
        'signatureImport output',
        signatureOutput64Error,
        () => secp256k1.signatureImport(bad64(), derSignature)
      )
      rejectsSpoof(
        'ecdsaSign output',
        signatureOutput64Error,
        () => rawSign(bad64(), message, validPrivateKey)
      )
      rejectsSpoof(
        'ecdsaSign message',
        messageError,
        () => rawSign(new Uint8Array(64), bad32(), validPrivateKey)
      )
      rejectsSpoof(
        'ecdsaSign private key',
        privateKeyError,
        () => rawSign(new Uint8Array(64), message, bad32())
      )
      rejectsSpoof(
        'ecdsaSign default nonce data',
        /^RangeError: options.data must be a 32-byte Uint8Array$/,
        () => rawSign(
          new Uint8Array(64),
          message,
          validPrivateKey,
          bad32()
        )
      )
      rejectsSpoof(
        'ecdsaVerify signature',
        signatureError,
        () => secp256k1.ecdsaVerify(bad64(), message, publicKey)
      )
      rejectsSpoof(
        'ecdsaVerify message',
        messageError,
        () => secp256k1.ecdsaVerify(signature, bad32(), publicKey)
      )
      rejectsSpoof(
        'ecdsaRecover signature',
        signatureError,
        () => secp256k1.ecdsaRecover(
          new Uint8Array(33),
          bad64(),
          0,
          message
        )
      )
      rejectsSpoof(
        'ecdsaRecover message',
        messageError,
        () => secp256k1.ecdsaRecover(
          new Uint8Array(33),
          signature,
          0,
          bad32()
        )
      )
      rejectsSpoof(
        'ecdh default output',
        /^RangeError: output must be a 32-byte Uint8Array$/,
        () => rawEcdh(bad32(), validPrivateKey)
      )
      rejectsSpoof(
        'ecdh private key',
        privateKeyError,
        () => rawEcdh(new Uint8Array(32), bad32())
      )
      rejectsSpoof(
        'ecdh x buffer',
        /^RangeError: options.xbuf must be a 32-byte Uint8Array$/,
        () => rawEcdh(
          new Uint8Array(32),
          validPrivateKey,
          () => new Uint8Array(32),
          bad32(),
          new Uint8Array(32)
        )
      )
      rejectsSpoof(
        'ecdh y buffer',
        /^RangeError: options.ybuf must be a 32-byte Uint8Array$/,
        () => rawEcdh(
          new Uint8Array(32),
          validPrivateKey,
          () => new Uint8Array(32),
          new Uint8Array(32),
          bad32()
        )
      )

      t.end()
    })

    t.test('nonce data (ecdsaSign options.data)', (t) => {
      const message = new Uint8Array(32)
      const sign = (data) => secp256k1.ecdsaSign(
        { signature: new Uint8Array(64), recid: null },
        message,
        validPrivateKey,
        data,
        undefined
      )

      t.equal(
        sign(new Uint8Array(32)),
        0,
        'accepts exact 32-byte data for the default nonce function'
      )
      t.throws(
        () => sign(new Uint8Array(16)),
        /^RangeError: options.data must be a 32-byte Uint8Array$/,
        'rejects undersized data before it is read as rfc6979 entropy'
      )

      // With a custom nonce function the 32-byte rule no longer applies: data of
      // any length is handed to the callback unchanged, never read as entropy
      // here. The default path accepts only exactly 32 bytes as extra entropy.
      const validNonce = new Uint8Array(32)
      validNonce.fill(1)
      const customData = new Uint8Array(42)
      let received = null
      t.equal(
        secp256k1.ecdsaSign(
          { signature: new Uint8Array(64), recid: null },
          message,
          validPrivateKey,
          customData,
          function () { received = arguments[3]; return validNonce }
        ),
        0,
        'accepts any-length data when a custom nonce function is supplied'
      )
      t.equal(
        received,
        customData,
        'hands the data to the nonce function unchanged'
      )

      t.end()
    })

    t.test('callback result must be a Uint8Array of the right kind', (t) => {
      // The nonce and hash callbacks return a value straight into a 32-byte
      // memcpy. A Uint16Array(16) has 32 bytes and a valid .Data() pointer, so a
      // guard that trusted ByteLength alone would copy it as if it were a
      // Uint8Array. The guard checks TypedArrayType(), so both callbacks reject
      // it and the operation fails. See GHSA-mwf5-hpj8-xjjc.
      const message = new Uint8Array(32)
      const wrongKindNonce = new Uint16Array(16)
      wrongKindNonce.fill(1)
      t.equal(
        secp256k1.ecdsaSign(
          { signature: new Uint8Array(64), recid: null },
          message,
          validPrivateKey,
          undefined,
          () => wrongKindNonce
        ),
        1,
        'a wrong-kind nonce function result fails signing'
      )

      // A real public key so ecdh runs the DH and actually reaches the hash
      // function, rather than short-circuiting on an unparseable key.
      const publicKey = new Uint8Array(33)
      secp256k1.publicKeyCreate(publicKey, validPrivateKey, true)
      t.equal(
        secp256k1.ecdh(
          new Uint8Array(32), publicKey, validPrivateKey, undefined,
          () => new Uint16Array(16), new Uint8Array(32), new Uint8Array(32)
        ),
        2,
        'a wrong-kind hash function result fails ecdh'
      )

      t.end()
    })

    t.test('callback state is isolated across reentrant calls', (t) => {
      const message = new Uint8Array(32)
      const nonce = new Uint8Array(32)
      nonce[31] = 1

      let outerNonceCalls = 0
      let innerNonceCalls = 0
      const innerSignature = { signature: new Uint8Array(64), recid: null }
      const outerSignature = { signature: new Uint8Array(64), recid: null }

      const innerNoncefn = () => {
        innerNonceCalls += 1
        return nonce
      }
      const outerNoncefn = () => {
        outerNonceCalls += 1
        if (outerNonceCalls === 1) {
          t.equal(
            secp256k1.ecdsaSign(
              innerSignature,
              message,
              validPrivateKey,
              undefined,
              innerNoncefn
            ),
            0,
            'a nested signature succeeds'
          )
          return new Uint8Array(32)
        }
        return nonce
      }

      t.equal(
        secp256k1.ecdsaSign(
          outerSignature,
          message,
          validPrivateKey,
          undefined,
          outerNoncefn
        ),
        0,
        'the outer signature succeeds after retrying its own callback'
      )
      t.equal(outerNonceCalls, 2, 'the outer call retains its nonce function')
      t.equal(innerNonceCalls, 1, 'the nested call does not replace outer state')

      const publicKey = new Uint8Array(33)
      secp256k1.publicKeyCreate(publicKey, validPrivateKey)

      const outerHash = new Uint8Array(32)
      outerHash.fill(0x11)
      const innerHash = new Uint8Array(1)
      innerHash[0] = 0x22
      const outerOutput = new Uint8Array(32)
      const innerOutput = new Uint8Array(1)

      t.equal(
        secp256k1.ecdh(
          outerOutput,
          publicKey,
          validPrivateKey,
          undefined,
          () => {
            t.equal(
              secp256k1.ecdh(
                innerOutput,
                publicKey,
                validPrivateKey,
                undefined,
                () => innerHash,
                new Uint8Array(32),
                new Uint8Array(32)
              ),
              0,
              'a nested ecdh succeeds'
            )
            return outerHash
          },
          new Uint8Array(32),
          new Uint8Array(32)
        ),
        0,
        'the outer ecdh retains its original output length'
      )
      t.same(innerOutput, innerHash, 'the nested result is copied')
      t.same(outerOutput, outerHash, 'the outer result is copied')

      t.end()
    })

    t.test('callback exceptions do not poison later calls', (t) => {
      const message = new Uint8Array(32)
      const nonce = new Uint8Array(32)
      nonce[31] = 1

      t.throws(
        () => secp256k1.ecdsaSign(
          { signature: new Uint8Array(64), recid: null },
          message,
          validPrivateKey,
          undefined,
          () => { throw new Error('nonce callback failed') }
        ),
        /^Error: nonce callback failed$/,
        'a nonce callback exception is propagated'
      )
      t.equal(
        secp256k1.ecdsaSign(
          { signature: new Uint8Array(64), recid: null },
          message,
          validPrivateKey,
          undefined,
          () => nonce
        ),
        0,
        'signing still succeeds after a callback exception'
      )

      const publicKey = new Uint8Array(33)
      secp256k1.publicKeyCreate(publicKey, validPrivateKey)
      t.throws(
        () => secp256k1.ecdh(
          new Uint8Array(32),
          publicKey,
          validPrivateKey,
          undefined,
          () => { throw new Error('hash callback failed') },
          new Uint8Array(32),
          new Uint8Array(32)
        ),
        /^Error: hash callback failed$/,
        'a hash callback exception is propagated'
      )
      t.equal(
        secp256k1.ecdh(
          new Uint8Array(32),
          publicKey,
          validPrivateKey,
          undefined,
          () => new Uint8Array(32),
          new Uint8Array(32),
          new Uint8Array(32)
        ),
        0,
        'ecdh still succeeds after a callback exception'
      )

      t.end()
    })

    t.test('outputs are revalidated after callback detachment', (t) => {
      const message = new Uint8Array(32)
      const nonce = new Uint8Array(32)
      nonce[31] = 1

      const signatureOutput = new Uint8Array(64)
      t.throws(
        () => secp256k1.ecdsaSign(
          { signature: signatureOutput, recid: null },
          message,
          validPrivateKey,
          undefined,
          () => {
            global.structuredClone(signatureOutput.buffer, {
              transfer: [signatureOutput.buffer]
            })
            return nonce
          }
        ),
        /^RangeError: signature output must remain a 64-byte Uint8Array$/,
        'signing rejects an output detached in the nonce callback'
      )

      const publicKey = new Uint8Array(33)
      secp256k1.publicKeyCreate(publicKey, validPrivateKey)
      const ecdhOutput = new Uint8Array(32)
      t.throws(
        () => secp256k1.ecdh(
          ecdhOutput,
          publicKey,
          validPrivateKey,
          undefined,
          () => {
            global.structuredClone(ecdhOutput.buffer, {
              transfer: [ecdhOutput.buffer]
            })
            return new Uint8Array(32)
          },
          new Uint8Array(32),
          new Uint8Array(32)
        ),
        /^RangeError: output must remain the same length during ecdh$/,
        'ecdh rejects an output detached in the hash callback'
      )

      t.end()
    })

    t.test('outputs are revalidated after callback growth', (t) => {
      const SharedArrayBufferConstructor = global.SharedArrayBuffer
      const canGrowSharedArrayBuffer =
        typeof SharedArrayBufferConstructor === 'function' &&
        typeof SharedArrayBufferConstructor.prototype.grow === 'function'

      if (!canGrowSharedArrayBuffer) {
        t.pass('growable SharedArrayBuffer is not supported by this runtime')
        t.end()
        return
      }

      const message = new Uint8Array(32)
      const nonce = new Uint8Array(32)
      nonce[31] = 1

      const signatureBuffer = new SharedArrayBufferConstructor(64, {
        maxByteLength: 65
      })
      const signatureOutput = new Uint8Array(signatureBuffer)
      t.throws(
        () => secp256k1.ecdsaSign(
          { signature: signatureOutput, recid: null },
          message,
          validPrivateKey,
          undefined,
          () => {
            signatureBuffer.grow(65)
            return nonce
          }
        ),
        /^RangeError: signature output must remain a 64-byte Uint8Array$/,
        'signing rejects an output whose length changed in the nonce callback'
      )

      const publicKey = new Uint8Array(33)
      secp256k1.publicKeyCreate(publicKey, validPrivateKey)
      const ecdhBuffer = new SharedArrayBufferConstructor(32, {
        maxByteLength: 33
      })
      const ecdhOutput = new Uint8Array(ecdhBuffer)
      t.throws(
        () => secp256k1.ecdh(
          ecdhOutput,
          publicKey,
          validPrivateKey,
          undefined,
          () => {
            ecdhBuffer.grow(33)
            return new Uint8Array(32)
          },
          new Uint8Array(32),
          new Uint8Array(32)
        ),
        /^RangeError: output must remain the same length during ecdh$/,
        'ecdh rejects an output whose length changed in the hash callback'
      )

      t.end()
    })

    t.test('hash buffers (ecdh options.xbuf / options.ybuf)', (t) => {
      // The custom hash function memcpy's 32 bytes into xbuf and ybuf, so both
      // must be validated before the write. A dummy public key is fine: the
      // length checks run before it is parsed.
      const publicKey = new Uint8Array(33)
      const hashfn = () => new Uint8Array(32)

      t.throws(
        () => secp256k1.ecdh(
          new Uint8Array(32), publicKey, validPrivateKey, undefined,
          hashfn, new Uint8Array(16), undefined
        ),
        /^RangeError: options.xbuf must be a 32-byte Uint8Array$/,
        'rejects an undersized xbuf before the 32-byte write'
      )
      t.throws(
        () => secp256k1.ecdh(
          new Uint8Array(32), publicKey, validPrivateKey, undefined,
          hashfn, new Uint8Array(32), new Uint8Array(16)
        ),
        /^RangeError: options.ybuf must be a 32-byte Uint8Array$/,
        'rejects an undersized ybuf before the 32-byte write'
      )

      t.end()
    })

    t.test('ignores a spoofed length property', (t) => {
      // 1-byte buffer masquerading as 32 bytes via an own `length` property.
      const spoofed = new Uint8Array(1)
      Object.defineProperty(spoofed, 'length', { value: 32, configurable: true })
      t.equal(spoofed.length, 32, 'sanity: spoofed length reads as 32')

      t.throws(
        () => secp256k1.privateKeyVerify(spoofed),
        /^RangeError: private key must be a 32-byte Uint8Array$/,
        'read path uses the native byte length, not the spoofed one'
      )
      t.throws(
        () => secp256k1.privateKeyNegate(spoofed),
        /^RangeError: private key must be a 32-byte Uint8Array$/,
        'write path uses the native byte length, not the spoofed one'
      )

      // Subclass exposing a fake `length` getter.
      class Spoofed extends Uint8Array {
        get length () { return 32 }
      }
      t.throws(
        () => secp256k1.privateKeyVerify(new Spoofed(1)),
        /^RangeError: private key must be a 32-byte Uint8Array$/,
        'subclass length getter is ignored'
      )

      t.end()
    })

    t.end()
  })
}
