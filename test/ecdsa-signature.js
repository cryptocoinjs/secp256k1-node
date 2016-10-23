import * as util from './util'

const messages = util.messages

export default function (t, secp256k1) {
  t.test('ecdsa.signature.normalize', (t) => {
    t.test('signature should be a Buffer', (t) => {
      t.throws(() => {
        secp256k1.ecdsa.signature.normalize(null)
      }, new RegExp(`TypeError: ${messages.ECDSA_SIGNATURE_TYPE_INVALID}`))
      t.end()
    })

    t.test('invalid length', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey).slice(1)
        secp256k1.ecdsa.signature.normalize(signature)
      }, new RegExp(`RangeError: ${messages.ECDSA_SIGNATURE_LENGTH_INVALID}`))
      t.end()
    })

    t.test('parse fail (r equal N)', (t) => {
      t.throws(() => {
        const signature = Buffer.concat([
          util.ec.curve.n.toArrayLike(Buffer, 'be', 32),
          util.BN_ONE.toArrayLike(Buffer, 'be', 32)
        ])
        secp256k1.ecdsa.signature.normalize(signature)
      }, new RegExp(`Error: ${messages.ECDSA_SIGNATURE_PARSE_FAIL}`))
      t.end()
    })

    t.test('normalize return same signature (s equal n/2)', (t) => {
      const signature = Buffer.concat([
        util.BN_ONE.toArrayLike(Buffer, 'be', 32),
        util.ec.nh.toArrayLike(Buffer, 'be', 32)
      ])
      const result = secp256k1.ecdsa.signature.normalize(signature)
      t.same(result, signature)
      t.end()
    })

    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()

        const sigObj = util.sign(message, privateKey)
        const result = secp256k1.ecdsa.signature.normalize(sigObj.signature)
        t.same(result, sigObj.signatureLowS)
        t.end()
      })
    }

    t.end()
  })

  t.test('ecdsa.signature.export', (t) => {
    t.test('signature should be a Buffer', (t) => {
      t.throws(() => {
        secp256k1.ecdsa.signature.export(null)
      }, new RegExp(`TypeError: ${messages.ECDSA_SIGNATURE_TYPE_INVALID}`))
      t.end()
    })

    t.test('invalid length', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const message = util.getMessage()
        const signature = util.getSignature(message, privateKey).slice(1)
        secp256k1.ecdsa.signature.export(signature)
      }, new RegExp(`RangeError: ${messages.ECDSA_SIGNATURE_LENGTH_INVALID}`))
      t.end()
    })

    t.test('parse fail (r equal N)', (t) => {
      t.throws(() => {
        const signature = Buffer.concat([
          util.ec.n.toArrayLike(Buffer, 'be', 32),
          util.BN_ONE.toArrayLike(Buffer, 'be', 32)
        ])
        secp256k1.ecdsa.signature.export(signature)
      }, new RegExp(`Error: ${messages.ECDSA_SIGNATURE_PARSE_FAIL}`))
      t.end()
    })

    t.end()
  })

  t.test('ecdsa.signature.import', (t) => {
    t.test('signature should be a Buffer', (t) => {
      t.throws(() => {
        secp256k1.ecdsa.signature.import(null)
      }, new RegExp(`TypeError: ${messages.ECDSA_SIGNATURE_TYPE_INVALID}`))
      t.end()
    })

    t.test('parse fail', (t) => {
      t.throws(() => {
        secp256k1.ecdsa.signature.import(Buffer.allocUnsafe(1))
      }, new RegExp(`Error: ${messages.ECDSA_SIGNATURE_PARSE_DER_FAIL}`))
      t.end()
    })

    t.test('parse not bip66 signature', (t) => {
      const signature = Buffer.from('308002204171936738571ff75ec0c56c010f339f1f6d510ba45ad936b0762b1b2162d8020220152670567fa3cc92a5ea1a6ead11741832f8aede5ca176f559e8a46bb858e3f6', 'hex')
      t.throws(() => {
        secp256k1.ecdsa.signature.import(signature)
      })
      t.end()
    })

    t.end()
  })

  t.test('ecdsa.signature.importLax', (t) => {
    t.test('signature should be a Buffer', (t) => {
      t.throws(() => {
        secp256k1.ecdsa.signature.importLax(null)
      }, new RegExp(`TypeError: ${messages.ECDSA_SIGNATURE_TYPE_INVALID}`))
      t.end()
    })

    t.test('parse fail', (t) => {
      t.throws(() => {
        secp256k1.ecdsa.signature.importLax(Buffer.allocUnsafe(1))
      }, new RegExp(`Error: ${messages.ECDSA_SIGNATURE_PARSE_DER_FAIL}`))
      t.end()
    })

    t.test('parse not bip66 signature', (t) => {
      const signature = Buffer.from('308002204171936738571ff75ec0c56c010f339f1f6d510ba45ad936b0762b1b2162d8020220152670567fa3cc92a5ea1a6ead11741832f8aede5ca176f559e8a46bb858e3f6', 'hex')
      t.doesNotThrow(() => {
        secp256k1.ecdsa.signature.importLax(signature)
      })
      t.end()
    })

    t.end()
  })

  t.test('ecdsa.signature.export/ecdsa.signature.import', (t) => {
    if (!util.env.EDGE_ONLY) {
      util.repeat(t, 'random tests', util.env.REPEAT, (t) => {
        const message = util.getMessage()
        const privateKey = util.getPrivateKey()

        const signature = util.sign(message, privateKey).signatureLowS

        const der = secp256k1.ecdsa.signature.export(signature)
        t.same(secp256k1.ecdsa.signature.import(der), signature)
        t.same(secp256k1.ecdsa.signature.importLax(der), signature)
        t.end()
      })
    }

    t.end()
  })
}
