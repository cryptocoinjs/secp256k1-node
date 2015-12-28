'use strict'

var BN = require('bn.js')

var P = 'ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f'
var N = 'ffffffff ffffffff ffffffff fffffffe baaedce6 af48a03b bfd25e8c d0364141'
var Gx = '79be667e f9dcbbac 55a06295 ce870b07 029bfcdb 2dce28d9 59f2815b 16f81798'
var Gy = '483ada77 26a3c465 5da4fbfc 0e1108a8 fd17b448 a6855419 9c47d08f fb10d4b8'

var endo = {
  'beta': '7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee',
  'lambda': '5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72',
  'basis': [
    {
      'a': '3086d221a7d46bcde86c90e49284eb15',
      'b': '-e4437ed6010e88286f547fa90abfe4c3'
    },
    {
      'a': '114ca50f7a8e2f3f657c1108d9d44cfd8',
      'b': '3086d221a7d46bcde86c90e49284eb15'
    }
  ]
}

var red = BN.red('k256')

module.exports = {
  p: new BN(P, 'hex'),
  b: new BN(7).toRed(red),
  n: new BN(N, 'hex'),
  nh: new BN(N, 'hex').ushrn(1),

  endo: {
    beta: new BN(endo.beta, 'hex').toRed(red),
    lambda: new BN(endo.lambda, 'hex'),
    basis: [{
      a: new BN(endo.basis[0].a, 'hex'),
      b: new BN(endo.basis[0].b, 'hex')
    }, {
      a: new BN(endo.basis[1].a, 'hex'),
      b: new BN(endo.basis[1].b, 'hex')
    }]
  },

  red: red,
  zero: new BN(0).toRed(red),
  one: new BN(1).toRed(red),

  initG: function () {
    var ECPointG = require('./ecpointg')
    var gx = new BN(Gx, 'hex').toRed(red)
    var gy = new BN(Gy, 'hex').toRed(red)
    module.exports.g = new ECPointG(gx, gy)
  }
}
