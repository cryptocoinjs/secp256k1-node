'use strict'

var BN = require('bn.js')

var ecparams = require('./ecparams')
var ECJPoint = require('./ecjpoint')
var util = require('./util')

/**
 * @class ECPoint
 * @constructor
 * @param {BN} x
 * @param {BN} y
 */
function ECPoint (x, y) {
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
 * @return {?ECPoint}
 */
ECPoint.fromPublicKey = function (publicKey) {
  var first = publicKey[0]
  var x
  var y

  if (publicKey.length === 33 && (first === 0x02 || first === 0x03)) {
    x = new BN(publicKey.slice(1, 33))

    // overflow
    if (x.cmp(ecparams.p) >= 0) {
      return null
    }

    // create from X
    x = x.toRed(ecparams.red)
    y = x.redSqr().redIMul(x).redIAdd(ecparams.b).redSqrt()
    if ((first === 0x03) !== y.fromRed().isOdd()) {
      y = y.redNeg()
    }

    return new ECPoint(x, y)
  }

  if (publicKey.length === 65 && (first === 0x04 || first === 0x06 || first === 0x07)) {
    x = new BN(publicKey.slice(1, 33))
    y = new BN(publicKey.slice(33, 65))

    // overflow
    if (x.cmp(ecparams.p) >= 0 || y.cmp(ecparams.p) >= 0) {
      return null
    }

    // is odd flag
    if ((first === 0x06 || first === 0x07) && y.isOdd() !== (first === 0x07)) {
      return null
    }

    // convert to red
    x = x.toRed(ecparams.red)
    y = y.toRed(ecparams.red)

    // x*x*x + 7 = y*y
    if (x.redSqr().redIMul(x).redIAdd(ecparams.b).redISub(y.redSqr()).cmpn(0) !== 0) {
      return null
    }

    return new ECPoint(x, y)
  }

  return null
}

/**
 * @param {boolean} compressed
 * @return {Buffer}
 */
ECPoint.prototype.toPublicKey = function (compressed) {
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
 * @return {ECPoint}
 */
ECPoint.fromECJPoint = function (p) {
  if (p.inf) {
    return new ECPoint(null, null)
  }

  var zinv = p.z.redInvm()
  var zinv2 = zinv.redSqr()
  var ax = p.x.redMul(zinv2)
  var ay = p.y.redMul(zinv2).redMul(zinv)

  return new ECPoint(ax, ay)
}

/**
 * @return {ECJPoint}
 */
ECPoint.prototype.toECJPoint = function () {
  if (this.inf) {
    return new ECJPoint(null, null, null)
  }

  return new ECJPoint(this.x, this.y, ecparams.one)
}

/**
 * @return {ECPoint}
 */
ECPoint.prototype.neg = function () {
  if (this.inf) {
    return this
  }

  return new ECPoint(this.x, this.y.redNeg())
}

/**
 * @param {ECPoint} p
 * @return {ECPoint}
 */
ECPoint.prototype.add = function (p) {
  // O + P = P
  if (this.inf) {
    return p
  }

  // P + O = P
  if (p.inf) {
    return this
  }

  if (this.x.cmp(p.x) === 0) {
    // P + P = 2P
    if (this.y.cmp(p.y) === 0) {
      return this.dbl()
    }

    // P + (-P) = O
    return new ECPoint(null, null)
  }

  // s = (y - yp) / (x - xp)
  // nx = s^2 - x - xp
  // ny = s * (x - nx) - y
  var s = this.y.redSub(p.y)
  if (s.cmpn(0) !== 0) {
    s = s.redMul(this.x.redSub(p.x).redInvm())
  }

  var nx = s.redSqr().redISub(this.x).redISub(p.x)
  var ny = s.redMul(this.x.redSub(nx)).redISub(this.y)
  return new ECPoint(nx, ny)
}

/**
 * @return {ECPoint}
 */
ECPoint.prototype.dbl = function () {
  if (this.inf) {
    return this
  }

  // 2P = O
  var yy = this.y.redAdd(this.y)
  if (yy.cmpn(0) === 0) {
    return new ECPoint(null, null)
  }

  // s = (3 * x^2) / (2 * y)
  // nx = s^2 - 2*x
  // ny = s * (x - nx) - y
  var x2 = this.x.redSqr()
  var s = x2.redAdd(x2).redIAdd(x2).redMul(yy.redInvm())

  var nx = s.redSqr().redISub(this.x.redAdd(this.x))
  var ny = s.redMul(this.x.redSub(nx)).redISub(this.y)
  return new ECPoint(nx, ny)
}

/**
 * @param {BN} num
 * @return {ECPoint}
 */
ECPoint.prototype.mul = function (num) {
  // Algorithm 3.36 Window NAF method for point multiplication
  var nafPoints = this._getNAFPoints(4)
  var points = nafPoints.points

  // Get NAF form
  var naf = util.getNAF(num, nafPoints.wnd)

  // Add `this`*(N+1) for every w-NAF index
  var acc = new ECJPoint(null, null, null)
  for (var i = naf.length - 1; i >= 0; i--) {
    // Count zeroes
    for (var k = 0; i >= 0 && naf[i] === 0; i--) {
      k++
    }
    if (i >= 0) {
      k++
    }
    acc = acc.dblp(k)

    if (i < 0) {
      break
    }

    // J +- P
    var z = naf[i]
    if (z > 0) {
      acc = acc.mixedAdd(points[(z - 1) >> 1])
    } else {
      acc = acc.mixedAdd(points[(-z - 1) >> 1].neg())
    }
  }

  return ECPoint.fromECJPoint(acc)
}

/**
 * @param {BN} k1
 * @param {ECPoint} p2
 * @param {BN} k2
 * @return {ECPoint}
 */
ECPoint.prototype.mulAdd = function (k1, p2, k2) {
  var p1 = this

  var nafPointsP1 = p1._getNAFPoints(1)
  var nafPointsP2 = p2._getNAFPoints(1)
  var wnd = [nafPointsP1.points, nafPointsP2.points]
  var naf = [util.getNAF(k1, nafPointsP1.wnd), util.getNAF(k2, nafPointsP2.wnd)]

  var acc = new ECJPoint(null, null, null)
  var tmp = new Array(2)
  for (var i = Math.max(naf[0].length, naf[1].length); i >= 0; i--) {
    var k = 0

    for (; i >= 0; ++k, --i) {
      tmp[0] = naf[0][i] | 0
      tmp[1] = naf[1][i] | 0

      if (tmp[0] !== 0 || tmp[1] !== 0) {
        break
      }
    }

    if (i >= 0) {
      k++
    }

    acc = acc.dblp(k)

    if (i < 0) {
      break
    }

    for (var jj = 0; jj < 2; jj++) {
      var z = tmp[jj]
      var p
      if (z === 0) {
        continue
      } else if (z > 0) {
        p = wnd[jj][z >> 1]
      } else if (z < 0) {
        p = wnd[jj][-z >> 1].neg()
      }

      // hack: ECPoint detection
      if (p.z === undefined) {
        acc = acc.mixedAdd(p)
      } else {
        acc = acc.add(p)
      }
    }
  }

  return ECPoint.fromECJPoint(acc)
}

/**
 * @param {number} wnd
 * @return {{wnd: number, points: ECPoint[]}}
 */
ECPoint.prototype._getNAFPoints = function (wnd) {
  if (wnd === 1) {
    return {wnd: 1, points: [this]}
  }

  var points = new Array((1 << wnd) - 1)
  points[0] = this
  var dbl = this.dbl()
  for (var i = 1; i < points.length; ++i) {
    points[i] = points[i - 1].add(dbl)
  }

  return {wnd: wnd, points: points}
}

module.exports = ECPoint
