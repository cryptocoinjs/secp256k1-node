'use strict'

var BN = require('bn.js')

var P = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F'
var N = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'
var Gx = '79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798'
var Gy = '483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8'

var red = BN.red('k256')

module.exports = {
  p: new BN(P, 'hex'),
  b: new BN(7).toRed(red),
  n: new BN(N, 'hex'),
  nh: new BN(N, 'hex').ushrn(1),

  red: red,
  zero: new BN(0).toRed(red),
  one: new BN(1).toRed(red),

  gx: new BN(Gx, 'hex').toRed(red),
  gy: new BN(Gy, 'hex').toRed(red)
}
