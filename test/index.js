var chai = require('chai')
var chaiAsPromised = require('chai-as-promised')
chai.use(chaiAsPromised)

var repeat = global.__env__ && global.__env__.RANDOM_TESTS_REPEAT ||
             process.env.RANDOM_TESTS_REPEAT ||
             10
repeat = parseInt(repeat, 10)

var isTravis = global.__env__ && global.__env__.TRAVIS || process.env.TRAVIS || false

/**
 * @param {Object} secp256k1
 * @param {string} description
 */
function runTests (secp256k1, description) {
  describe(description, function () {
    this.timeout(repeat * 500 * (isTravis ? 5 : 1))

    require('./secretkey')(secp256k1, {repeat: repeat})
    require('./publickey')(secp256k1, {repeat: repeat})
    require('./signature')(secp256k1, {repeat: repeat})
    require('./sign')(secp256k1, {repeat: repeat})
    require('./verify')(secp256k1, {repeat: repeat})
    require('./recover')(secp256k1, {repeat: repeat})
    require('./ecdh')(secp256k1, {repeat: repeat})
    require('./sign-verify-recover')(secp256k1, {repeat: repeat})
  })
}

if (!process.browser) {
  runTests(require('../bindings'), 'secp256k1 bindings')
}

runTests(require('../elliptic'), 'elliptic package')
