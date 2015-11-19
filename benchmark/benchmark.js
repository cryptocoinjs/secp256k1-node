var benchmark = require('benchmark')

var bindings = require('../bindings')
var elliptic = require('../elliptic')

var ecdsa = require('./ecdsa')
var util = require('./util')

function createSuite (suiteName, objs) {
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

  Object.keys(objs).forEach(function (fnName) {
    var obj = objs[fnName]
    suite.add(fnName, obj.fn, obj.options)
  })

  return suite
}

var message = util.getMessage()
var pair = util.generateKeyPair()
var signature = util.createSignature(message, pair.privateKey)

// sign
createSuite('sign', {
  bindings: {
    fn: function () {
      bindings.signSync(message, pair.privateKey)
    }
  },
  elliptic: {
    fn: function () {
      elliptic.signSync(message, pair.privateKey)
    }
  },
  ecdsa: {
    fn: function () {
      ecdsa.signSync(message, pair.privateKey)
    }
  }
}).run()

// verify
createSuite('verify', {
  bindings: {
    fn: function () {
      bindings.verifySync(message, signature, pair.publicKey)
    }
  },
  elliptic: {
    fn: function () {
      elliptic.verifySync(message, signature, pair.publicKey)
    }
  },
  ecdsa: {
    fn: function () {
      ecdsa.verifySync(message, signature, pair.publicKey)
    }
  }
}).run()
