'use strict'

var util = require('./util')

/**
 * @param {Object} secp256k1
 * @param {string} description
 */
function test (secp256k1, description) {
  describe(description, function () {
    this.timeout(util.env.repeat * 100 * (util.env.isTravis ? 5 : 1))

    before(function () {
      util.setSeed(util.env.seed)
    })

    require('./privatekey')(secp256k1)
    require('./publickey')(secp256k1)
    require('./signature')(secp256k1)
    require('./ecdsa')(secp256k1)
    // require('./ecdh')(secp256k1)
  })
}

if (!process.browser) { require('./bn') }
require('./rfc6979/sha256')
require('./rfc6979/hmac-sha256')
require('./rfc6979')
require('./ecpoints')

if (!process.browser) { test(require('../bindings'), 'secp256k1 bindings') }
test(require('../elliptic'), 'elliptic')
test(require('../js'), 'pure js')
