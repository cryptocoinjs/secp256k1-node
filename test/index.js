'use strict'
var test = require('tape')
var util = require('./util')

function testAPI (secp256k1, description) {
  test(description, function (t) {
    util.setSeed(util.env.seed)

    require('./privatekey')(t, secp256k1)
    require('./publickey')(t, secp256k1)
    require('./signature')(t, secp256k1)
    require('./ecdsa')(t, secp256k1)
    require('./ecdh')(t, secp256k1)

    t.end()
  })
}

if (!process.browser && process.platform !== 'win32') require('./bn')
require('./ecpoint')
require('./ecjpoint')

if (!process.browser) testAPI(require('../bindings'), 'secp256k1 bindings')
testAPI(require('../elliptic'), 'elliptic')
testAPI(require('../js'), 'pure js')
