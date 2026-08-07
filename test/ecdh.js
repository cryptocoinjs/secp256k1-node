const util = require('./util')

module.exports = (t, secp256k1) => {
  t.test('ecdh', (t) => {
    t.test('arg: invalid public key', (t) => {
      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = null
        secp256k1.ecdh(publicKey, privateKey)
      }, /^Error: Expected public key to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed.slice(1)
        secp256k1.ecdh(publicKey, privateKey)
      }, /^Error: Expected public key to be an Uint8Array with length \[33, 65]$/, 'should have length 33 or 65')

      t.throws(() => {
        const privateKey = util.getPrivateKey()
        const publicKey = util.getPublicKey(privateKey).compressed
        publicKey[0] = 0x01
        secp256k1.ecdh(publicKey, privateKey)
      }, /^Error: Public Key could not be parsed$/, 'should throw on invalid public key: version 0x01')
      t.end()
    })

    t.test('arg: invalid private key', (t) => {
      t.throws(() => {
        const privateKey = null
        const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        secp256k1.ecdh(publicKey, privateKey)
      }, /^Error: Expected private key to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        const privateKey = util.getPrivateKey().slice(1)
        const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        secp256k1.ecdh(publicKey, privateKey)
      }, /^Error: Expected private key to be an Uint8Array with length 32$/, 'should have length 32')

      t.throws(() => {
        const privateKey = util.ec.n.toArrayLike(Buffer, 'be', 32)
        const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        secp256k1.ecdh(publicKey, privateKey)
      }, /^Error: Scalar was invalid \(zero or overflow\)$/, 'should throw for overflowed private key')

      t.throws(() => {
        const privateKey = util.ec.curve.zero.fromRed().toArrayLike(Buffer, 'be', 32)
        const publicKey = util.getPublicKey(util.getPrivateKey()).compressed
        secp256k1.ecdh(publicKey, privateKey)
      }, /^Error: Scalar was invalid \(zero or overflow\)$/, 'should throw for zero private key')

      t.end()
    })

    t.test('arg: invalid options', (t) => {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed

      t.throws(() => {
        secp256k1.ecdh(publicKey, privateKey, null)
      }, /^Error: Expected options to be an Object$/, 'should be an Object')

      t.throws(() => {
        secp256k1.ecdh(publicKey, privateKey, Number(42))
      }, /^Error: Expected options to be an Object$/, 'should be an Object')

      t.throws(() => {
        secp256k1.ecdh(publicKey, privateKey, { data: null })
      }, /^Error: Expected options.data to be an Uint8Array$/, 'data should be an Uint8Array')

      t.throws(() => {
        secp256k1.ecdh(publicKey, privateKey, { hashfn: null })
      }, /^Error: Expected options.hashfn to be a Function$/, 'hashfn should be a Function')

      t.throws(() => {
        secp256k1.ecdh(publicKey, privateKey, { hashfn () {}, xbuf: null })
      }, /^Error: Expected options.xbuf to be an Uint8Array$/, 'xbuf should be an Uint8Array')

      t.throws(() => {
        secp256k1.ecdh(publicKey, privateKey, { hashfn () {}, xbuf: new Uint8Array(42) })
      }, /^Error: Expected options.xbuf to be an Uint8Array with length 32$/, 'xbuf should have length 32')

      t.throws(() => {
        secp256k1.ecdh(publicKey, privateKey, { hashfn () {}, xbuf: new Uint8Array(32), ybuf: null })
      }, /^Error: Expected options.ybuf to be an Uint8Array$/, 'ybuf should be an Uint8Array')

      t.throws(() => {
        secp256k1.ecdh(publicKey, privateKey, { hashfn () {}, xbuf: new Uint8Array(32), ybuf: new Uint8Array(42) })
      }, /^Error: Expected options.ybuf to be an Uint8Array with length 32$/, 'ybuf should have length 32')

      t.end()
    })

    t.test('arg: invalid output', (t) => {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed

      t.throws(() => {
        secp256k1.ecdh(publicKey, privateKey, {}, null)
      }, /^Error: Expected output to be an Uint8Array$/, 'should be an Uint8Array')

      t.throws(() => {
        secp256k1.ecdh(publicKey, privateKey, {}, new Uint8Array(42))
      }, /^Error: Expected output to be an Uint8Array with length 32$/, 'should have length 32')

      secp256k1.ecdh(publicKey, privateKey, {}, (len) => {
        t.same(len, 32, 'compressed form should ask Uint8Array with length 32')
        return new Uint8Array(len)
      })

      t.plan(3)
      t.end()
    })

    t.test('hashfn usage', (t) => {
      const privateKey = util.getPrivateKey()
      const publicKey = util.getPublicKey(privateKey).compressed
      const data = new Uint8Array(42)
      const xbuf = new Uint8Array(32)
      const ybuf = new Uint8Array(32)
      const result = util.getMessage()

      t.test('hashfn call', (t) => {
        function hashfn () {
          t.same(arguments.length, 3)
          t.same(arguments[0], xbuf)
          t.same(arguments[1], ybuf)
          t.same(arguments[2], data)
          return result
        }

        const hash = secp256k1.ecdh(publicKey, privateKey, { data, hashfn, xbuf, ybuf }, Buffer.alloc(result.length))
        t.same(hash, result)

        t.end()
      })

      t.test('options are read once', (t) => {
        const reads = { data: 0, hashfn: 0, xbuf: 0, ybuf: 0 }
        const hashfn = () => result
        const options = {
          get data () {
            reads.data += 1
            return data
          },
          get hashfn () {
            reads.hashfn += 1
            return hashfn
          },
          get xbuf () {
            reads.xbuf += 1
            return xbuf
          },
          get ybuf () {
            reads.ybuf += 1
            return ybuf
          }
        }

        const hash = secp256k1.ecdh(
          publicKey,
          privateKey,
          options,
          Buffer.alloc(result.length)
        )

        t.same(hash, result, 'the captured options are used for ecdh')
        t.same(
          reads,
          { data: 1, hashfn: 1, xbuf: 1, ybuf: 1 },
          'each option is captured exactly once'
        )
        t.end()
      })

      t.test('zero-length custom output', (t) => {
        const output = new Uint8Array(0)
        const hash = secp256k1.ecdh(
          publicKey,
          privateKey,
          { hashfn: () => new Uint8Array(0) },
          output
        )

        t.equal(hash, output, 'returns the caller-provided empty output')
        t.equal(hash.byteLength, 0, 'accepts an empty hash result')
        t.end()
      })

      t.test('custom output and hash results use real byte lengths', (t) => {
        const spoofedResult = new Uint8Array(result)
        const expected = new Uint8Array(result)
        Object.defineProperty(spoofedResult, 'length', {
          value: 1e6,
          configurable: true
        })
        const output = new Uint8Array(result.byteLength)
        Object.defineProperty(output, 'length', {
          value: 1e6,
          configurable: true
        })
        const hash = secp256k1.ecdh(
          publicKey,
          privateKey,
          { hashfn: () => spoofedResult },
          output
        )

        t.equal(hash, output, 'returns the caller-provided output')
        t.same(
          hash,
          expected,
          'a spoofed hash length does not change the copied result'
        )

        const undersizedResult = new Uint8Array(1)
        Object.defineProperty(undersizedResult, 'length', {
          value: output.byteLength,
          configurable: true
        })
        t.throws(
          () => secp256k1.ecdh(
            publicKey,
            privateKey,
            { hashfn: () => undersizedResult },
            new Uint8Array(output.byteLength)
          ),
          /^Error: Scalar was invalid \(zero or overflow\)$/,
          'an undersized hash result cannot masquerade as the output size'
        )
        t.end()
      })

      t.test('invalid hash', (t) => {
        t.throws(() => {
          secp256k1.ecdh(publicKey, privateKey, { hashfn: () => null })
        }, /^Error: Expected output to be an Uint8Array$/, 'result of hashfn should be Uint8Array')

        t.throws(() => {
          secp256k1.ecdh(publicKey, privateKey, { hashfn: () => new Uint8Array(2) }, new Uint8Array(1))
        }, /^Error: Scalar was invalid \(zero or overflow\)$/, 'result of hashfn should be Uint8Array with same length as output')

        t.throws(() => {
          secp256k1.ecdh(publicKey, privateKey, { hashfn: () => new Uint16Array(16) }, new Uint8Array(32))
        }, /^Error: Scalar was invalid \(zero or overflow\)$/, 'result of hashfn should not be another typed-array kind')

        t.end()
      })

      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, (t) => {
      const privateKey1 = util.getPrivateKey()
      const publicKey1 = util.getPublicKey(privateKey1).compressed
      const privateKey2 = util.getPrivateKey()
      const publicKey2 = util.getPublicKey(privateKey2).compressed

      const shared1 = secp256k1.ecdh(publicKey1, privateKey2)
      const shared2 = secp256k1.ecdh(publicKey2, privateKey1)
      t.same(shared1, shared2)
    })

    t.end()
  })
}
