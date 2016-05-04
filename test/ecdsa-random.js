'use strict'
var assert = require('assert')
var getRandomBytes = require('crypto').randomBytes

var bindings = require('../bindings')
var secp256k1js = require('../js')
var util = require('./util')

var STEP_REPEAT = 100000

var t = {
  test: function (name, fn) {
    fn({ end: function () {} })
  }
}

var repeat = util.env.repeat
var seed = util.env.seed
while (repeat > 0) {
  util.setSeed(seed)
  util.repeat(t, 'random tests', (repeat % STEP_REPEAT) || STEP_REPEAT, function (t) {
    var message = util.getMessage()
    var privateKey = util.getPrivateKey()
    try {
      var publicKey = bindings.publicKeyCreate(privateKey)
      var expected = bindings.sign(message, privateKey)

      var sigObj = secp256k1js.sign(message, privateKey)
      assert.same(sigObj.signature, expected.signature)
      assert.same(sigObj.recovery, expected.recovery)

      var isValid = secp256k1js.verify(message, sigObj.signature, publicKey)
      assert.same(isValid, true)

      var publicKey2 = secp256k1js.recover(message, sigObj.signature, sigObj.recovery, true)
      assert.same(publicKey2, publicKey)
    } catch (err) {
      console.log('\nMessage:', message.toString('hex'))
      console.log('Private key:', privateKey.toString('hex'))
      throw err
    }

    t.end()
  })

  repeat -= STEP_REPEAT
  seed = getRandomBytes(32)
}
