'use strict'

var BN = require('bn.js')

var P = exports.P = new BN('ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f', 'hex')
var N = exports.N = new BN('ffffffff ffffffff ffffffff fffffffe baaedce6 af48a03b bfd25e8c d0364141', 'hex')
var NH = exports.NH = N.ushrn(1)

var red = BN.red('k256')
var redB = new BN(7).toRed(red)

/**
 * @param {Buffer} privateKey
 * @return {boolean}
 */
exports.isValidPrivateKey = function (privateKey) {
  var bn = new BN(privateKey)
  return bn.cmp(N) === -1 && bn.cmpn(0) > 0
}

/**
 * @class Point
 * @constructor
 * @param {BN} x
 * @param {BN} y
 */
var Point = exports.Point = function (x, y) {
  if (x === null && y === null) {
    this.x = this.y = null
    this.inf = true
  } else {
    this.x = x
    this.y = y
    this.inf = false
  }
}

Point.G = new Point(
  new BN('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 'hex').toRed(red),
  new BN('483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8', 'hex').toRed(red))

/**
 * @param {Buffer} publicKey
 * @return {?Point}
 */
Point.fromPublicKey = function (publicKey) {
  var first = publicKey[0]

  if (publicKey.length === 33 && (first === 0x02 || first === 0x03)) {
    var x = new BN(publicKey.slice(1, 33))

    // overflow
    if (x.cmp(P) >= 0) {
      return null
    }

    // create from X
    x = x.toRed(red)
    var y = x.redSqr().redIMul(x).redIAdd(redB).redSqrt()
    if ((first === 0x03) !== y.fromRed().isOdd()) {
      y = y.redNeg()
    }

    return new Point(x, y)
  }

  if (publicKey.length === 65 && (first === 0x04 || first === 0x06 || first === 0x07)) {
    var x = new BN(publicKey.slice(1, 33))
    var y = new BN(publicKey.slice(33, 65))

    // overflow
    if (x.cmp(P) >= 0 || y.cmp(P) >= 0) {
      return null
    }

    // is odd flag
    if ((first === 0x06 || first === 0x07) && y.isOdd() !== (first === 0x07)) {
      return null
    }

    // convert to red
    x = x.toRed(red)
    y = y.toRed(red)

    // x*x*x + 7 = y*y
    if (x.redSqr().redIMul(x).redIAdd(redB).redISub(y.redSqr()).cmpn(0) !== 0) {
      return null
    }

    return new Point(x, y)
  }

  return null
}

/**
 * @param {boolean} compressed
 * @return {Buffer}
 */
Point.prototype.toPublicKey = function (compressed) {
  var publicKey

  var x = this.x.fromRed()
  var y = this.y.fromRed()

  if (compressed) {
    publicKey = new Buffer(33)
    publicKey[0] = y.isOdd() ? 0x03 : 0x02
    new Buffer(x.toArray(null, 32)).copy(publicKey, 1)
  } else {
    publicKey = new Buffer(65)
    publicKey[0] = 0x04
    new Buffer(x.toArray(null, 32)).copy(publicKey, 1)
    new Buffer(y.toArray(null, 32)).copy(publicKey, 33)
  }

  return publicKey
}
