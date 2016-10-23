import test from 'tape'
import vectors from 'hash-test-vectors'
import sha256 from '../../es/js/sha256'

for (let i = 0; i < vectors.length; ++i) {
  test(`sha256, NIST vector ${i}`, (t) => {
    const vector = vectors[i]
    const input = Buffer.from(vector.input, 'base64')

    t.same(sha256(input).toString('hex'), vector.sha256)

    t.end()
  })
}
