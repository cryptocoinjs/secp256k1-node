const benchmark = require('benchmark')
const ProgressBar = require('progress')

const util = require('../test/util')
const implementations = {
  bindings: require('../bindings'),
  elliptic: require('../elliptic'),
  ecdsa: require('./ecdsa')
}

let fixtureIndex = 0
const fixtures = new Array(1000)
function getNextFixture () {
  const fixture = fixtures[fixtureIndex++]
  if (fixtureIndex === fixtures.length) fixtureIndex = 0

  return fixture
}

const progressBar = new ProgressBar(':percent (:current/:total), :elapseds elapsed, eta :etas', {
  total: fixtures.length,
  stream: util.progressStream
})

util.setSeed(util.env.seed)
for (let i = 0; i < fixtures.length; ++i) {
  const fixture = {}
  fixture.privateKey = util.getPrivateKey()
  fixture.publicKey = util.getPublicKey(fixture.privateKey).compressed
  fixture.message = util.getMessage()
  fixture.sigObj = util.sign(fixture.message, fixture.privateKey)
  fixtures[i] = fixture
  progressBar.tick()
}
console.log('Create ' + fixtures.length + ' fixtures')
console.log('++++++++++++++++++++++++++++++++++++++++++++++++++')

function runSuite (suiteName, testFunctionGenerator) {
  const suite = new benchmark.Suite(suiteName, {
    onStart () {
      console.log('Benchmarking: ' + suiteName)
      console.log('--------------------------------------------------')
    },
    onCycle (event) {
      console.log(String(event.target))
    },
    onError (event) {
      console.error(event.target.error)
    },
    onComplete () {
      console.log('==================================================')
    }
  })

  for (const [name, impl] of Object.entries(implementations)) {
    if (impl[suiteName] === undefined) continue

    suite.add(name, testFunctionGenerator(impl), {
      onStart () {
        fixtureIndex = 0
      },
      onCycle () {
        fixtureIndex = 0
      }
    })
  }

  suite.run()
}

runSuite('publicKeyCreate', (secp256k1) => () => {
  const fixture = getNextFixture()
  secp256k1.publicKeyCreate(fixture.privateKey)
})

runSuite('ecdsaSign', (secp256k1) => () => {
  const fixture = getNextFixture()
  secp256k1.ecdsaSign(fixture.message, fixture.privateKey)
})

runSuite('ecdsaVerify', (secp256k1) => () => {
  const fixture = getNextFixture()
  secp256k1.ecdsaVerify(fixture.sigObj.signature, fixture.message, fixture.publicKey)
})

runSuite('ecdsaRecover', (secp256k1) => () => {
  const fixture = getNextFixture()
  secp256k1.ecdsaRecover(fixture.sigObj.signature, fixture.sigObj.recid, fixture.message)
})

runSuite('ecdh', (secp256k1) => () => {
  const fixture = getNextFixture()
  secp256k1.ecdh(fixture.publicKey, fixture.privateKey)
})
