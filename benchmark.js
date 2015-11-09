var Benchmark = require('benchmark')
var randomBytes = require('crypto').randomBytes
var secp256k1 = require('bindings')('secp256k1')

var pks = new Array(10000)
for (var i = 0; i < pks.length; ++i) {
  pks[i] = randomBytes(32)
}
var pkIndex1 = 0
var pkIndex2 = 0

new Benchmark.Suite()
  .add('api v2.x', function () {
    if (pkIndex1 === pks.length) { pkIndex1 = 0 }
    secp256k1.publicKeyCreate(pks[pkIndex1++])
  })
  .add('with object', function () {
    if (pkIndex2 === pks.length) { pkIndex2 = 0 }
    secp256k1.publicKeyCreateNew(pks[pkIndex2++]).serialize()
  })
  .on('cycle', function (event) {
    console.log(String(event.target))
  })
  .on('complete', function () {
    console.log('Fastest is ' + this.filter('fastest').pluck('name'))
  })
  .run()
