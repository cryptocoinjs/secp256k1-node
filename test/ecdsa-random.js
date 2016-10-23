import assert from 'assert'
import { randomBytes as getRandomBytes } from 'crypto'
import bindings from '../bindings'
import secp256k1js from '../js'
import * as util from './util'

const STEP_REPEAT = 100000

const t = {
  test: (name, fn) => {
    fn({ end: () => {} })
  }
}

let seed = util.env.SEED
let repeat = util.env.REPEAT
while (repeat > 0) {
  util.setSeed(seed)
  util.repeat(t, 'random tests', (repeat % STEP_REPEAT) || STEP_REPEAT, (t) => {
    const message = util.getMessage()
    const privateKey = util.getPrivateKey()
    try {
      const publicKey = bindings.publicKey.create(privateKey)
      const expected = bindings.ecdsa.sign(message, privateKey)

      const sigObj = secp256k1js.ecdsa.sign(message, privateKey)
      assert.same(sigObj.signature, expected.signature)
      assert.same(sigObj.recovery, expected.recovery)

      const isValid = secp256k1js.ecdsa.verify(message, sigObj.signature, publicKey)
      assert.same(isValid, true)

      const publicKey2 = secp256k1js.ecdsa.recover(message, sigObj.signature, sigObj.recovery, true)
      assert.same(publicKey2, publicKey)
    } catch (err) {
      console.log(`\nMessage: ${message.toString('hex')}`)
      console.log(`Private key: ${privateKey.toString('hex')}`)
      throw err
    }

    t.end()
  })

  repeat -= STEP_REPEAT
  seed = getRandomBytes(32)
}
