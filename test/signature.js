const util = require('./util')

module.exports = (t, secp256k1) => {
  t.test('signatureNormalize', (t) => {
    t.test('arg: invalid signature should be a Buffer', (t) => {
      t.throws(() => {
        secp256k1.signatureNormalize(null)
      }, /^Error: Expected signature to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey).slice(1)
        secp256k1.signatureNormalize(signature)
      }, /^Error: Expected signature to be an Uint8Array with length 64$/, 'should have length 64')

      t.throws(() => {
        const signature = Buffer.concat([
          util.ec.curve.n.toArrayLike(Buffer, 'be', 32),
          util.BN_ONE.toArrayLike(Buffer, 'be', 32)
        ])
        secp256k1.signatureNormalize(signature)
      }, /^Error: Signature could not be parsed$/, 'should throw error for invalid signature: r equal to N')

      t.end()
    })

    t.test('do not change valid signature (s equal to N/2)', (t) => {
      const signature = Buffer.concat([
        util.BN_ONE.toArrayLike(Buffer, 'be', 32),
        util.ec.nh.toArrayLike(Buffer, 'be', 32)
      ])
      const result = secp256k1.signatureNormalize(Buffer.from(signature))
      t.same(result, signature)
      t.end()
    })

    t.test('normalize signature (s equal to N/2 + 1)', (t) => {
      const signature = Buffer.concat([
        util.BN_ONE.toArrayLike(Buffer, 'be', 32),
        util.ec.nh.toArrayLike(Buffer, 'be', 32)
      ])
      const signature1 = new util.BN(signature).iaddn(1).toArrayLike(Buffer, 'be', 64)
      const result = secp256k1.signatureNormalize(signature1)
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
    t.test('invalid: signature', (t) => {
      t.throws(() => {
        secp256k1.signatureExport(null)
      }, /^Error: Expected signature to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey).slice(1)
        secp256k1.signatureExport(signature)
      }, /^Error: Expected signature to be an Uint8Array with length 64$/, 'should have length 64')

      t.throws(() => {
        const signature = Buffer.concat([
          util.ec.n.toArrayLike(Buffer, 'be', 32),
          util.BN_ONE.toArrayLike(Buffer, 'be', 32)
        ])
        secp256k1.signatureExport(signature)
      }, /^Error: Signature could not be parsed$/, 'should throw error for invalid signature: r equal to N')

      t.end()
    })

    t.test('arg: invalid output', (t) => {
      const privateKey = util.getPrivateKey()
      const message = util.getMessage()
      const signature = util.getSignature(message, privateKey)

      t.throws(() => {
        secp256k1.signatureExport(signature, null)
      }, /^Error: Expected output to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        secp256k1.signatureExport(signature, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 72$/, 'should have length 72 if compressed')

      secp256k1.signatureExport(signature, (len) => {
        t.same(len, 72, 'should ask Uint8Array with length 72')
        return new Uint8Array(len)
      })

      t.plan(3)
      t.end()
    })

    t.end()
  })

  t.test('signatureImport', (t) => {
    t.test('invalid: signature', (t) => {
      t.throws(() => {
        secp256k1.signatureImport(null)
      }, /^Error: Expected signature to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        secp256k1.signatureImport(new Uint8Array(42))
      }, /^Error: Signature could not be parsed$/, 'should throw error for invalid signature')

      t.end()
    })

    t.test('arg: invalid output', (t) => {
      const signature = Buffer.from('3006020101020101', 'hex')

      t.throws(() => {
        secp256k1.signatureImport(signature, null)
      }, /^Error: Expected output to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        secp256k1.signatureImport(signature, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 64$/, 'should have length 64 if compressed')

      secp256k1.signatureImport(signature, (len) => {
        t.same(len, 64, 'should ask Uint8Array with length 64')
        return new Uint8Array(len)
      })

      t.plan(3)
      t.end()
    })

    t.end()
  })

  t.test('signatureExport/signatureImport', (t) => {
    util.repeat(t, 'random tests', util.env.repeat, (t) => {
      const message = util.getMessage()
      const privateKey = util.getPrivateKey()
      const signature = util.sign(message, privateKey).signatureLowS

      const exported = secp256k1.signatureExport(signature)
      const imported = secp256k1.signatureImport(exported, Buffer.alloc)
      t.same(imported, signature)
    })

    t.end()
  })
}
