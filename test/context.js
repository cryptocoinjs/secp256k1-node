const util = require('./util')

module.exports = (t, secp256k1) => {
  t.test('contextRandomize', (t) => {
    t.test('arg: invalid seed', (t) => {
      t.throws(() => {
        secp256k1.contextRandomize()
      }, /^Error: Expected seed to be an Uint8Array or null$/, 'should be be an Uint8Array or null')

      t.throws(() => {
        const seed = new Uint8Array(42)
        secp256k1.contextRandomize(seed)
      }, /^Error: Expected seed to be an Uint8Array with length 32$/, 'should have length 32')

      t.end()
    })

    t.test('valid seed', (t) => {
      t.doesNotThrow(() => {
        const seed = util.getMessage()
        secp256k1.contextRandomize(seed)
      }, 'pass random buffer with length 32')

      t.doesNotThrow(() => {
        secp256k1.contextRandomize(null)
      }, 'pass seed as null')

      t.end()
    })
  })
}
