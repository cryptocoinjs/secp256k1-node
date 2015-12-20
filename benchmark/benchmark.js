var benchmark = require('benchmark')

var util = require('../test/util')
var packages = {
  bindings: require('../bindings'),
  elliptic: require('./elliptic'),
  ecdsa: require('./ecdsa')
}

var fixtureIndex = 0
var fixtures = new Array(1000)
for (var i = 0; i < fixtures.length; ++i) {
  var fixture = {}
  fixture.privateKey = util.getPrivateKey()
  fixture.publicKey = util.getPublicKey(fixture.privateKey).compressed
  fixture.message = util.getMessage()
  fixture.signature = util.getSignature(fixture.message, fixture.privateKey)
  fixtures[i] = fixture
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
      console.log('--------------------------------------------------')
      console.log('Fastest is ' + this.filter('fastest').pluck('name'))
      console.log('==================================================')
    }
  })

  Object.keys(packages).forEach(function (packageName) {
    suite.add(packageName, testFunctionGenerator(packages[packageName]), {
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

runSuite('sign', function (package) {
  return function () {
    var fixture = fixtures[fixtureIndex++]
    if (fixtureIndex === fixtures.length) {
      fixtureIndex = 0
    }

    package.sign(fixture.message, fixture.privateKey)
  }
})

runSuite('verify', function (package) {
  return function () {
    var fixture = fixtures[fixtureIndex++]
    if (fixtureIndex === fixtures.length) {
      fixtureIndex = 0
    }

    package.verify(fixture.message, fixture.signature, fixture.publicKey)
  }
})
