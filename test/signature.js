const util = require('./util')

module.exports = (t, secp256k1) => {
  t.test('signatureNormalize', (t) => {
    t.test('signature should be a Buffer', (t) => {
      t.throws(() => {
        secp256k1.signatureNormalize(null)
      }, /^Error: Expected signature to be an Uint8Array$/)
      t.end()
    })

    t.test('invalid length', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey).slice(1)
        secp256k1.signatureNormalize(signature)
      }, /^Error: Expected signature to be an Uint8Array with length 64$/)
      t.end()
    })

    t.test('parse fail (r equal N)', (t) => {
      t.throws(() => {
        const signature = Buffer.concat([
          util.ec.curve.n.toArrayLike(Buffer, 'be', 32),
          util.BN_ONE.toArrayLike(Buffer, 'be', 32)
        ])
        secp256k1.signatureNormalize(signature)
      }, /^Error: Signature could not be parsed$/)
      t.end()
    })

    t.test('normalize return same signature (s equal n/2)', (t) => {
      const signature = Buffer.concat([
        util.BN_ONE.toArrayLike(Buffer, 'be', 32),
        util.ec.nh.toArrayLike(Buffer, 'be', 32)
      ])
      const result = secp256k1.signatureNormalize(Buffer.from(signature))
      t.same(result, signature)
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, (t) => {
      const message = util.getMessage()
      const privateKey = util.getPrivateKey()

      const sigObj = util.sign(message, privateKey)
      const result = secp256k1.signatureNormalize(sigObj.signature, Buffer.alloc)
      t.same(result, sigObj.signatureLowS)
    })

    t.end()
  })

  t.test('signatureExport', (t) => {
    t.test('signature should be a Buffer', (t) => {
      t.throws(() => {
        secp256k1.signatureExport(null)
      }, /^Error: Expected signature to be an Uint8Array$/)
      t.end()
    })

    t.test('invalid length', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey).slice(1)
        secp256k1.signatureExport(signature)
      }, /^Error: Expected signature to be an Uint8Array with length 64$/)
      t.end()
    })

    t.test('parse fail (r equal N)', (t) => {
      t.throws(() => {
        const signature = Buffer.concat([
          util.ec.n.toArrayLike(Buffer, 'be', 32),
          util.BN_ONE.toArrayLike(Buffer, 'be', 32)
        ])
        secp256k1.signatureExport(signature)
      }, /^Error: Signature could not be parsed$/)
      t.end()
    })

    t.test('invalid output', (t) => {
      const privateKey = util.getPrivateKey()
      const message = util.getMessage()
      const signature = util.getSignature(message, privateKey)

      t.throws(() => {
        secp256k1.signatureExport(signature, null)
      }, /^Error: Expected output to be an Uint8Array$/)

      t.throws(() => {
        secp256k1.signatureExport(signature, new Uint8Array(71))
      }, /^Error: Expected output to be an Uint8Array with length 72$/)

      t.end()
    })

    t.test('output as function', (t) => {
      t.plan(1)

      const privateKey = util.getPrivateKey()
      const message = util.getMessage()
      const signature = util.getSignature(message, privateKey)

      secp256k1.signatureExport(signature, (len) => {
        t.same(len, 72)
        return new Uint8Array(72)
      })

      t.end()
    })

    t.end()
  })

  t.test('signatureImport', (t) => {
    t.test('signature should be a Buffer', (t) => {
      t.throws(() => {
        secp256k1.signatureImport(null)
      }, /^Error: Expected signature to be an Uint8Array$/)
      t.end()
    })

    t.test('parse fail', (t) => {
      t.throws(() => {
        secp256k1.signatureImport(Buffer.alloc(1))
      }, /^Error: Signature could not be parsed$/)
      t.end()
    })

    t.test('parse not bip66 signature', (t) => {
      const signature = Buffer.from('308002204171936738571ff75ec0c56c010f339f1f6d510ba45ad936b0762b1b2162d8020220152670567fa3cc92a5ea1a6ead11741832f8aede5ca176f559e8a46bb858e3f6', 'hex')
      t.throws(() => {
        secp256k1.signatureImport(signature)
      })
      t.end()
    })

    t.test('invalid output', (t) => {
      const sig = Buffer.from('3006020101020101', 'hex')

      t.throws(() => {
        secp256k1.signatureImport(sig, null)
      }, /^Error: Expected output to be an Uint8Array$/)

      t.throws(() => {
        secp256k1.signatureImport(sig, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 64$/)

      t.end()
    })

    t.test('output as function', (t) => {
      t.plan(1)

      const sig = Buffer.from('3006020101020101', 'hex')
      secp256k1.signatureImport(sig, (len) => {
        t.same(len, 64)
        return new Uint8Array(64)
      })

      t.end()
    })

    t.end()
  })
}
