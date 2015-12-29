'use strict'

var chai = require('chai')
var chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)

var util = require('./util')

/**
 * @param {Object} secp256k1
 * @param {string} description
 */
function test (secp256k1, description) {
  describe(description, function () {
    var repeat = util.env.repeat
    this.timeout(repeat * 100 * (util.env.isTravis ? 5 : 1))

    before(function () {
      util.setSeed(util.env.seed)
    })

    require('./privatekey')(secp256k1, {repeat: repeat})
    require('./publickey')(secp256k1, {repeat: repeat})
    require('./signature')(secp256k1, {repeat: repeat})
    require('./ecdsa')(secp256k1, {repeat: repeat})
    // require('./ecdh')(secp256k1, {repeat: repeat})
  })
}

if (!process.browser) {
  test(require('../bindings'), 'secp256k1 bindings')
}

test(require('../js'), 'pure js')

require('./rfc6979') // rf6979 tests
