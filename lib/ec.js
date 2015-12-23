'use strict'

var BN = require('bn.js')

var P = new BN('ffffffff ffffffff ffffffff ffffffff ffffffff ffffffff fffffffe fffffc2f', 'hex')
var N = new BN('ffffffff ffffffff ffffffff fffffffe baaedce6 af48a03b bfd25e8c d0364141', 'hex')
var red = BN.red('k256')
var redB = new BN(7).toRed(red)

/**
 * @class Point
 * @constructor
 * @param {BN} x
 * @param {BN} y
 */
function Point (x, y) {
  if (x === null && y === null) {
    this.x = this.y = null
    this.inf = true
  } else {
    this.x = x
    this.y = y
    this.inf = false
  }
}

/**
 * @param {Buffer} publicKey
 * @return {?Point}
 */
Point.fromPublicKey = function (publicKey) {
  var first = publicKey[0]
  var x
  var y

  if (publicKey.length === 33 && (first === 0x02 || first === 0x03)) {
    x = new BN(publicKey.slice(1, 33))

    // overflow
    if (x.cmp(P) >= 0) {
      return null
    }

    // create from X
    x = x.toRed(red)
    y = x.redSqr().redIMul(x).redIAdd(redB).redSqrt()
    if ((first === 0x03) !== y.fromRed().isOdd()) {
      y = y.redNeg()
    }

    return new Point(x, y)
  }

  if (publicKey.length === 65 && (first === 0x04 || first === 0x06 || first === 0x07)) {
    x = new BN(publicKey.slice(1, 33))
    y = new BN(publicKey.slice(33, 65))

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
  var x = this.x.fromRed()
  var y = this.y.fromRed()
  var publicKey

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

/**
 * @param {Point} p
 * @return {boolean}
 */
Point.prototype.eq = function (p) {
  return this === p ||
         this.inf === p.inf && (this.inf || this.x.cmp(p.x) === 0 && this.y.cmp(p.y) === 0)
}

/**
 * @return {Point}
 */
Point.prototype.neg = function () {
  if (this.inf) {
    return this
  }

  return new Point(this.x, this.y.redNeg())
}

/**
 * @param {Point} p
 * @return {Point}
 */
Point.prototype.add = function (p) {
  // O + P = P
  if (this.inf) {
    return p
  }

  // P + O = P
  if (p.inf) {
    return this
  }

  // P + P = 2P
  if (this.eq(p)) {
    return this.dbl()
  }

  // P + (-P) = O
  if (this.neg().eq(p)) {
    return new Point(null, null)
  }

  // P + Q = O
  if (this.x.cmp(p.x) === 0) {
    return new Point(null, null)
  }

  // nx = c^2 - x - xp
  // ny = c * (xp - nx) - yp
  // c = (y - yp) / (x - xp)
  var c = this.y.redSub(p.y)
  if (c.cmpn(0) !== 0) {
    c.redIMul(this.x.redSub(p.x).redInvm())
  }

  var nx = c.redSqr().redISub(this.x).redISub(p.x)
  var ny = c.redMul(this.x.redSub(nx)).redISub(this.y)
  return new Point(nx, ny)
}

/**
 * @return {Point}
 */
Point.prototype.dbl = function () {
  if (this.inf) {
    return this
  }

  // 2P = O
  var ys1 = this.y.redAdd(this.y)
  if (ys1.cmpn(0) === 0) {
    return new Point(null, null)
  }

  // nx = c^2 - 2*x
  // ny = c * (x - nx) - y
  // c = (3 * x^2 + a) / (2 * y)
  var x2 = this.x.redSqr()
  var dyinv = ys1.redInvm()
  var c = x2.redAdd(x2).redIAdd(x2).redIMul(dyinv)

  var nx = c.redSqr().redISub(this.x.redAdd(this.x))
  var ny = c.redMul(this.x.redSub(nx)).redISub(this.y)
  return new Point(nx, ny)
}

module.exports = {
  N: N,
  NH: N.ushrn(1),
  G: new Point(new BN('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798', 'hex').toRed(red),
               new BN('483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8', 'hex').toRed(red)),

  Point: Point
}
