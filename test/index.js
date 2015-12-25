'use strict'

var chai = require('chai')
var chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)
var getRandomBytes = require('crypto').randomBytes

var util = require('./util')

var privateKeySeed = getRandomBytes(32)
var tweakSeed = getRandomBytes(32)
var messageSeed = getRandomBytes(32)

/**
 * @param {Object} secp256k1
 * @param {string} description
 */
function runTests (secp256k1, description) {
  describe(description, function () {
    var repeat = util.getRepeat()
    this.timeout(repeat * 50 * (util.isTravis() ? 5 : 1))

    before(function () {
      util.getPrivateKeySetSeed(privateKeySeed)
      util.getTweakSetSeed(tweakSeed)
      util.getMessageSetSeed(messageSeed)
    })

    require('./privatekey')(secp256k1, {repeat: repeat})
    require('./publickey')(secp256k1, {repeat: repeat})
    require('./signature')(secp256k1, {repeat: repeat})
    require('./ecdsa')(secp256k1, {repeat: repeat})
    // require('./ecdh')(secp256k1, {repeat: repeat})
  })
}

if (!process.browser) {
  runTests(require('../bindings'), 'secp256k1 bindings')
}

runTests(require('../js'), 'pure js')
