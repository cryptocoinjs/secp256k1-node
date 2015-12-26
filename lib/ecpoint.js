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

  this.precomputed = null
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
  if (p.isInfinity()) {
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
 * @param {Object} [options]
 * @param {number} [options.wnd=8]
 */
ECPoint.prototype.precompute = function (options) {
  if (this.precomputed === null) {
    this.precomputed = {
      naf: this._getNAFPoints(Object(options).wnd || 8),
      doubles: this._getDoubles(Object(options).step || 4),
      beta: this._getBeta()
    }
  }

  return this
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

  // c = (y - yp) / (x - xp)
  // nx = c^2 - x - xp
  // ny = c * (xp - nx) - yp
  var c = this.y.redSub(p.y)
  if (c.cmpn(0) !== 0) {
    c = c.redMul(this.x.redSub(p.x).redInvm())
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

  // c = (3 * x^2 + a) / (2 * y)
  // nx = c^2 - 2*x
  // ny = c * (x - nx) - y
  var x2 = this.x.redSqr()
  var dyinv = ys1.redInvm()
  var c = x2.redAdd(x2).redIAdd(x2).redMul(dyinv)

  var nx = c.redSqr().redISub(this.x.redAdd(this.x))
  var ny = c.redMul(this.x.redSub(nx)).redISub(this.y)
  return new ECPoint(nx, ny)
}

/**
 * @param {BN} k
 * @return {ECPoint}
 */
ECPoint.prototype.mul = function (k) {
  if (this._hasDoubles(k)) {
    return this._fixedNafMul(this, k)
  }

  return this._endoWnafMulAdd([this], [k])
}

/**
 * @param {BN} k1
 * @param {ECPoint} p2
 * @param {BN} k2
 * @return {ECPoint}
 */
ECPoint.prototype.mulAdd = function (k1, p2, k2) {
  return this._endoWnafMulAdd([this, p2], [k1, k2])
}

/**
 * @param {BN} k
 * @return {boolean}
 */
ECPoint.prototype._hasDoubles = function (k) {
  if (this.precomputed === null) {
    return false
  }

  var doubles = this.precomputed.doubles
  return doubles.points.length >= Math.ceil((k.bitLength() + 1) / doubles.step)
}

/**
 * @param {number} step
 * @return {{step: number, points: ECPoint[]}
 */
ECPoint.prototype._getDoubles = function (step) {
  if (this.precomputed !== null) {
    return this.precomputed.doubles
  }

  var points = new Array(1 + Math.ceil(257 / step))
  points[0] = this

  var acc = this
  for (var i = 1; i < points.length; ++i) {
    for (var j = 0; j < step; j++) {
      acc = acc.dbl()
    }

    points[i] = acc
  }

  return {step: step, points: points}
}

/**
 * @param {ECPoint} p
 * @param {BN} num
 * @return {ECPoint}
 */
ECPoint.prototype._fixedNafMul = function (p, num) {
  var doubles = p._getDoubles()

  var naf = util.getNAF(num, 1)
  var I = (1 << (doubles.step + 1)) - (doubles.step % 2 === 0 ? 2 : 1)
  I /= 3

  var j
  var nafW

  // Translate into more windowed form
  var repr = []
  for (j = 0; j < naf.length; j += doubles.step) {
    nafW = 0
    for (var k = j + doubles.step - 1; k >= j; k--) {
      nafW = (nafW << 1) + naf[k]
    }

    repr.push(nafW)
  }

  var a = new ECJPoint(null, null, null)
  var b = new ECJPoint(null, null, null)
  for (var i = I; i > 0; i--) {
    for (j = 0; j < repr.length; j++) {
      nafW = repr[j]
      if (nafW === i) {
        b = b.mixedAdd(doubles.points[j])
      } else if (nafW === -i) {
        b = b.mixedAdd(doubles.points[j].neg())
      }
    }

    a = a.add(b)
  }

  return ECPoint.fromECJPoint(a)
}

/**
 * @param {BN} k
 * @return {k1: BN, k2: BN}
 */
ECPoint.prototype._endoSplit = function (k) {
  var basis = ecparams.endo.basis
  var v1 = basis[0]
  var v2 = basis[1]

  var c1 = v2.b.mul(k).divRound(ecparams.n)
  var c2 = v1.b.neg().mul(k).divRound(ecparams.n)

  var p1 = c1.mul(v1.a)
  var p2 = c2.mul(v2.a)
  var q1 = c1.mul(v1.b)
  var q2 = c2.mul(v2.b)

  // Calculate answer
  var k1 = k.sub(p1).sub(p2)
  var k2 = q1.add(q2).neg()
  return {k1: k1, k2: k2}
}

/**
 * @return {ECPoint}
 */
ECPoint.prototype._getBeta = function () {
  if (this.precomputed) {
    return this.precomputed.beta
  }

  return new ECPoint(this.x.redMul(ecparams.endo.beta), this.y)
}

/*
 * @param {ECPoint[]} points
 * @param {BN[]} coeffs
 * @return {ECPoint}
 */
ECPoint.prototype._endoWnafMulAdd = function (points, coeffs) {
  var npoints = new Array(4)
  var ncoeffs = new Array(4)

  for (var i = 0; i < points.length; i++) {
    var split = this._endoSplit(coeffs[i])
    var p = points[i]
    var beta = p._getBeta()

    if (split.k1.isNeg()) {
      split.k1.ineg()
      p = p.neg(true)
    }
    if (split.k2.isNeg()) {
      split.k2.ineg()
      beta = beta.neg(true)
    }

    npoints[i * 2] = p
    npoints[i * 2 + 1] = beta
    ncoeffs[i * 2] = split.k1
    ncoeffs[i * 2 + 1] = split.k2
  }

  return this._wnafMulAdd(npoints, ncoeffs, i * 2)
}

/**
 * @param {ECPoint[]} points
 * @param {BN[]} coeffs
 * @param {number} len
 * @return {ECPoint}
 */
ECPoint.prototype._wnafMulAdd = function (points, coeffs, len) {
  var wndWidth = new Array(4)
  var wnd = new Array(4)
  var naf = new Array(4)
  var i
  var j

  // Fill all arrays
  var max = 0
  for (i = 0; i < len; i++) {
    var point = points[i]
    var nafPoints = point._getNAFPoints(1)
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

  var acc = new ECJPoint(null, null, null)
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

      // hack: ECPoint detection
      if (p.z === undefined) {
        acc = acc.mixedAdd(p)
      } else {
        acc = acc.add(p)
      }
    }
  }

  // Zeroify references
  for (i = 0; i < len; i++) {
    wnd[i] = null
  }

  return ECPoint.fromECJPoint(acc)
}

/**
 * @param {number} wnd
 * @return {{wnd: number, points: ECPoint[]}}
 */
ECPoint.prototype._getNAFPoints = function (wnd) {
  if (this.precomputed !== null) {
    return this.precomputed.naf
  }

  var size = (1 << wnd) - 1
  var points = new Array(size)
  points[0] = this
  if (size > 1) {
    var dbl = this.dbl()
    for (var i = 1; i < size; ++i) {
      points[i] = points[i - 1].add(dbl)
    }
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
