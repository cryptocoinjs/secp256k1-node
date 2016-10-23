import test from 'tape'
import vectors from 'hash-test-vectors/hmac'
import sha256hmac from '../../es/js/sha256-hmac'

for (let i = 0; i < vectors.length; ++i) {
  test(`sha256 hmac, NIST vector ${i}`, (t) => {
    const vector = vectors[i]
    const key = Buffer.from(vector.key, 'hex')
    const data = Buffer.from(vector.data, 'hex')

    if (key.length === 32) t.same(sha256hmac(key, data).toString('hex'), vector.sha256)

    t.end()
  })
}
