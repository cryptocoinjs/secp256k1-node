'use strict'

var assert = require('assert')
var BN = require('bn.js')

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

  this.precomputed = null
}

ECPoint.red = BN.red('k256')
ECPoint.zero = new BN(0).toRed(ECPoint.red)
ECPoint.one = new BN(1).toRed(ECPoint.red)
ECPoint.b = new BN(7).toRed(ECPoint.red)

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
    if (x.cmp(ECPoint.red.m) >= 0) {
      return null
    }

    // create from X
    x = x.toRed(ECPoint.red)
    y = x.redSqr().redIMul(x).redIAdd(ECPoint.b).redSqrt()
    if ((first === 0x03) !== y.fromRed().isOdd()) {
      y = y.redNeg()
    }

    return new ECPoint(x, y)
  }

  if (publicKey.length === 65 && (first === 0x04 || first === 0x06 || first === 0x07)) {
    x = new BN(publicKey.slice(1, 33))
    y = new BN(publicKey.slice(33, 65))

    // overflow
    if (x.cmp(ECPoint.red.m) >= 0 || y.cmp(ECPoint.red.m) >= 0) {
      return null
    }

    // is odd flag
    if ((first === 0x06 || first === 0x07) && y.isOdd() !== (first === 0x07)) {
      return null
    }

    // convert to red
    x = x.toRed(ECPoint.red)
    y = y.toRed(ECPoint.red)

    // x*x*x + 7 = y*y
    if (x.redSqr().redIMul(x).redIAdd(ECPoint.b).redISub(y.redSqr()).cmpn(0) !== 0) {
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

ECPoint.prototype.toECJPoint = function () {
  if (this.inf) {
    return new ECPoint.ECJPoint(null, null, null)
  }

  return new ECPoint.ECJPoint(this.x, this.y, ECPoint.one)
}

/**
 * @param {Object} [options]
 * @param {number} [options.wnd=8]
 */
ECPoint.prototype.precompute = function (options) {
  if (this.precomputed === null) {
    this.precomputed = {
      naf: this._getNAFPoints(Object(options).wnd || 8)
    }
  }
}

/**
 * @param {ECPoint} p
 * @return {boolean}
 */
ECPoint.prototype.eq = function (p) {
  return this === p ||
         this.inf === p.inf && (this.inf || this.x.cmp(p.x) === 0 && this.y.cmp(p.y) === 0)
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

  // P + P = 2P
  if (this.eq(p)) {
    return this.dbl()
  }

  // P + (-P) = O
  if (this.neg().eq(p)) {
    return new ECPoint(null, null)
  }

  // P + Q = O
  if (this.x.cmp(p.x) === 0) {
    return new ECPoint(null, null)
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
  var ys1 = this.y.redAdd(this.y)
  if (ys1.cmpn(0) === 0) {
    return new ECPoint(null, null)
  }

  // nx = c^2 - 2*x
  // ny = c * (x - nx) - y
  // c = (3 * x^2 + a) / (2 * y)
  var x2 = this.x.redSqr()
  var dyinv = ys1.redInvm()
  var c = x2.redAdd(x2).redIAdd(x2).redIMul(dyinv)

  var nx = c.redSqr().redISub(this.x.redAdd(this.x))
  var ny = c.redMul(this.x.redSub(nx)).redISub(this.y)
  return new ECPoint(nx, ny)
}

/**
 * @param {BN} k
 * @return {ECPoint}
 */
ECPoint.prototype.mul = function (k) {
  return this._wnafMul(k)
}

/**
 * @param {BN} k1
 * @param {ECPoint} p2
 * @param {BN} k2
 * @return {ECPoint}
 */
ECPoint.prototype.mulAdd = function (k1, p2, k2) {
  var points = [this, p2]
  var coeffs = [k1, k2]
  return this._wnafMulAdd(1, points, coeffs, 2)
}

/**
 * @param {BN} num
 * @return {ECPoint}
 */
ECPoint.prototype._wnafMul = function (num) {
  // Precompute window
  var nafPoints = this._getNAFPoints(4)
  var points = nafPoints.points

  // Get NAF form
  var naf = util.getNAF(num, nafPoints.wnd)

  // Add `this`*(N+1) for every w-NAF index
  var acc = new ECPoint.ECJPoint(null, null, null)
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
    assert(z)
    var point = points[(Math.abs(z) - 1) >> 1]
    acc = acc.mixedAdd(z > 0 ? point : point.neg())
  }

  return acc.toECPoint()
}

/**
 * @param {number} defW
 * @param {ECPoint[]} points
 * @param {BN[]} coeffs
 * @param {number} len
 * @return {ECPoint}
 */
ECPoint.prototype._wnafMulAdd = function (defW, points, coeffs, len) {
  var wndWidth = new Array(4)
  var wnd = new Array(4)
  var naf = new Array(4)
  var i
  var j

  // Fill all arrays
  var max = 0
  for (i = 0; i < len; i++) {
    var point = points[i]
    var nafPoints = point._getNAFPoints(defW)
    wndWidth[i] = nafPoints.wnd
    wnd[i] = nafPoints.points
  }

  // Comb small window NAFs
  for (i = len - 1; i >= 1; i -= 2) {
    var a = i - 1
    var b = i
    if (wndWidth[a] !== 1 || wndWidth[b] !== 1) {
      naf[a] = util.getNAF(coeffs[a], wndWidth[a])
      naf[b] = util.getNAF(coeffs[b], wndWidth[b])
      max = Math.max(naf[a].length, max)
      max = Math.max(naf[b].length, max)
      continue
    }

    var comb = [
      points[a], /* 1 */
      null, /* 3 */
      null, /* 5 */
      points[b] /* 7 */
    ]

    // Try to avoid Projective points, if possible
    if (points[a].y.cmp(points[b].y) === 0) {
      comb[1] = points[a].add(points[b])
      comb[2] = points[a].toECJPoint().mixedAdd(points[b].neg())
    } else if (points[a].y.cmp(points[b].y.redNeg()) === 0) {
      comb[1] = points[a].toECJPoint().mixedAdd(points[b])
      comb[2] = points[a].add(points[b].neg())
    } else {
      comb[1] = points[a].ECJPoint().mixedAdd(points[b])
      comb[2] = points[a].ECJPoint().mixedAdd(points[b].neg())
    }

    var index = [
      -3, /* -1 -1 */
      -1, /* -1 0 */
      -5, /* -1 1 */
      -7, /* 0 -1 */
      0, /* 0 0 */
      7, /* 0 1 */
      5, /* 1 -1 */
      1, /* 1 0 */
      3  /* 1 1 */
    ]

    var jsf = util.getJSF(coeffs[a], coeffs[b])
    max = Math.max(jsf[0].length, max)
    naf[a] = new Array(max)
    naf[b] = new Array(max)
    for (j = 0; j < max; j++) {
      var ja = jsf[0][j] | 0
      var jb = jsf[1][j] | 0

      naf[a][j] = index[(ja + 1) * 3 + (jb + 1)]
      naf[b][j] = 0
      wnd[a] = comb
    }
  }

  var acc = new ECPoint.ECJPoint(null, null, null)
  var tmp = new Array(4)
  for (i = max; i >= 0; i--) {
    var k = 0

    for (; i >= 0; ++k, --i) {
      var zero = true
      for (j = 0; j < len; j++) {
        tmp[j] = naf[j][i] | 0
        if (tmp[j] !== 0) {
          zero = false
        }
      }

      if (!zero) {
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

    for (j = 0; j < len; j++) {
      var z = tmp[j]
      var p
      if (z === 0) {
        continue
      } else if (z > 0) {
        p = wnd[j][(z - 1) >> 1]
      } else if (z < 0) {
        p = wnd[j][(-z - 1) >> 1].neg()
      }

      acc = acc.mixedAdd(p)
    }
  }

  // Zeroify references
  for (i = 0; i < len; i++) {
    wnd[i] = null
  }

  return acc.toECPoint()
}

/**
 * @param {number} wnd
 * @return {{wnd: number, points: ECPoint[]}}
 */
ECPoint.prototype._getNAFPoints = function (wnd) {
  if (this.precomputed !== null) {
    return this.precomputed.naf
  }

  var points = [this]
  var max = (1 << wnd) - 1
  var dbl = max === 1 ? null : this.dbl()
  for (var i = 1; i < max; ++i) {
    points[i] = points[i - 1].add(dbl)
  }

  return {
    wnd: wnd,
    points: points
  }
}

/**
 * @return {boolean}
 */
ECPoint.prototype.isInfinity = function () {
  return this.inf
}

module.exports = ECPoint
