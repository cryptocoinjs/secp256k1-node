'use strict'

var BN = require('bn.js')

var P = 'ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f'
var N = 'ffffffff ffffffff ffffffff fffffffe baaedce6 af48a03b bfd25e8c d0364141'
var Gx = '79be667e f9dcbbac 55a06295 ce870b07 029bfcdb 2dce28d9 59f2815b 16f81798'
var Gy = '483ada77 26a3c465 5da4fbfc 0e1108a8 fd17b448 a6855419 9c47d08f fb10d4b8'

var red = BN.red('k256')

module.exports = {
  P: new BN(P, 'hex'),
  b: new BN(7).toRed(red),
  N: new BN(N, 'hex'),
  NH: new BN(N, 'hex').ushrn(1),

  red: red,
  ZERO: new BN(0).toRed(red),
  ONE: new BN(1).toRed(red),

  initG: function () {
    var ECPoint = require('./ecpoint')
    var gx = new BN(Gx, 'hex').toRed(red)
    var gy = new BN(Gy, 'hex').toRed(red)
    module.exports.G = new ECPoint(gx, gy).precompute()
  }
}
