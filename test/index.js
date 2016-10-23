import test from 'tape'
import testPrivateKey from './privatekey'
import testPublicKey from './publickey'
import testECDSASignature from './ecdsa-signature'
import testECDSA from './ecdsa'
// import testSchnorr from './schnorr'
import testECDH from './ecdh'
import * as util from './util'

function testAPI (secp256k1, description) {
  test(description, (t) => {
    util.setSeed(util.env.SEED)

    testPrivateKey(t, secp256k1)
    testPublicKey(t, secp256k1)
    testECDSASignature(t, secp256k1)
    testECDSA(t, secp256k1)
    // testSchnorr(t, secp256k1)
    testECDH(t, secp256k1)

    t.end()
  })
}

if (!process.browser) require('./js/bn')
require('./js/ecpoint')
require('./js/ecjpoint')
require('./js/sha256')
require('./js/sha256-hmac')

if (!process.browser) testAPI(require('../bindings'), 'secp256k1 bindings')
testAPI(require('../elliptic'), 'elliptic')
testAPI(require('../js'), 'pure js')
