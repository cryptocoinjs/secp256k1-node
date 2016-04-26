'use strict'
var benchmark = require('benchmark')
var ProgressBar = require('progress')

var util = require('../test/util')
var implementations = {
  bindings: require('../bindings'),
  secp256k1js: require('../js'),
  elliptic: require('../elliptic'),
  ecdsa: require('./ecdsa')
}

var fixtureIndex = 0
var fixtures = new Array(1000)
var getNextFixture = function () {
  var fixture = fixtures[fixtureIndex++]
  if (fixtureIndex === fixtures.length) fixtureIndex = 0

  return fixture
}

var progressBar = new ProgressBar(':percent (:current/:total), :elapseds elapsed, eta :etas', {
  total: fixtures.length,
  stream: util.progressStream
})

util.setSeed(util.env.seed)
for (var i = 0; i < fixtures.length; ++i) {
  var fixture = {}
  fixture.privateKey = util.getPrivateKey()
  fixture.publicKey = util.getPublicKey(fixture.privateKey).compressed
  fixture.message = util.getMessage()
  // fixture.signature = util.getSignature(fixture.message, fixture.privateKey)
  fixture.signature = implementations.secp256k1js.sign(fixture.message, fixture.privateKey).signature
  fixtures[i] = fixture
  progressBar.tick()
}
console.log('Create ' + fixtures.length + ' fixtures')
console.log('++++++++++++++++++++++++++++++++++++++++++++++++++')

function runSuite (suiteName, testFunctionGenerator) {
  var suite = new benchmark.Suite(suiteName, {
    onStart: function () {
      console.log('Benchmarking: ' + suiteName)
      console.log('--------------------------------------------------')
    },
    onCycle: function (event) {
      console.log(String(event.target))
    },
    onError: function (event) {
      console.error(event.target.error)
    },
    onComplete: function () {
      console.log('==================================================')
    }
  })

  Object.keys(implementations).forEach(function (name) {
    suite.add(name, testFunctionGenerator(implementations[name]), {
      onStart: function () {
        fixtureIndex = 0
      },
      onCycle: function () {
        fixtureIndex = 0
      }
    })
  })

  suite.run()
}

runSuite('publicKeyCreate', function (secp256k1) {
  return function () {
    var fixture = getNextFixture()
    secp256k1.publicKeyCreate(fixture.privateKey)
  }
})

runSuite('sign', function (secp256k1) {
  return function () {
    var fixture = getNextFixture()
    secp256k1.sign(fixture.message, fixture.privateKey)
  }
})

runSuite('verify', function (secp256k1) {
  return function () {
    var fixture = getNextFixture()
    secp256k1.verify(fixture.message, fixture.signature, fixture.publicKey)
  }
})
