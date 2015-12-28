'use strict'

var BN = require('bn.js')

var ecparams = require('./ecparams')
var ECPoint = require('./ecpoint')
var ECJPoint = require('./ecjpoint')
var util = require('./util')

/**
 * @class ECPointG
 * @constructor
 * @param {BN} gx
 * @param {BN} gy
 */
function ECPointG (gx, gy) {
  this.x = gx
  this.y = gy
  this.inf = false

  this.precomputed = {
    naf: this._getNAFPoints(8),
    doubles: this._getDoubles(4),
    beta: this._getBeta()
  }
}

/**
 * @return {ECJPoint}
 */
ECPointG.prototype.toECJPoint = function () {
  return new ECJPoint(this.x, this.y, ecparams.one)
}

/**
 * @param {boolean} _precompute
 * @return {ECPointG}
 */
ECPointG.prototype.neg = function (_precompute) {
  var point = new ECPoint(this.x, this.y.redNeg())
  if (_precompute && this.precomputed) {
    var pre = this.precomputed
    var negate = function (p) {
      return p.neg()
    }

    point.precomputed = {
      naf: {
        wnd: pre.naf.wnd,
        points: pre.naf.points.map(negate)
      },
      doubles: {
        step: pre.doubles.step,
        points: pre.doubles.points.map(negate)
      }
    }
  }

  return point
}

/**
 * @param {ECPoint} p
 * @return {ECPoint}
 */
ECPointG.prototype.add = ECPoint.prototype.add

/**
 * @return {ECPoint}
 */
ECPointG.prototype.dbl = ECPoint.prototype.dbl

/**
 * @param {BN} num
 * @return {ECPointG}
 */
ECPointG.prototype.mul = function (num) {
  // fixed NAF
  var step = this.precomputed.doubles.step
  var points = this.precomputed.doubles.points
  var negpoints = this.precomputed.doubles.negpoints

  var naf = util.getNAF(num, 1)
  var I = ((1 << (step + 1)) - (step % 2 === 0 ? 2 : 1)) / 3

  var j
  var nafW

  // Translate into more windowed form
  var repr = []
  for (j = 0; j < naf.length; j += step) {
    nafW = 0
    for (var k = j + step - 1; k >= j; k--) {
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
        b = b.mixedAdd(points[j])
      } else if (nafW === -i) {
        b = b.mixedAdd(negpoints[j])
      }
    }

    a = a.add(b)
  }

  return ECPoint.fromECJPoint(a)
}

/**
 * @param {BN} k1
 * @param {ECPointG} p2
 * @param {BN} k2
 * @return {ECPointG}
 */
ECPointG.prototype.mulAdd = function (k1, p2, k2) {
  return this._endoWnafMulAdd([this, p2], [k1, k2])
}

/**
 * @param {number} step
 * @return {{step: number, points: ECPointG[]}
 */
ECPointG.prototype._getDoubles = function (step) {
  var points = new Array(1 + Math.ceil(257 / step))
  points[0] = this

  var acc = this
  for (var i = 1; i < points.length; ++i) {
    for (var j = 0; j < step; j++) {
      acc = acc.dbl()
    }

    points[i] = acc
  }

  var neg = function (p) { return p.neg() }
  return {step: step, points: points, negpoints: points.map(neg)}
}

/**
 * @param {BN} k
 * @return {k1: BN, k2: BN}
 */
ECPointG.prototype._endoSplit = function (k) {
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
 * @return {ECPointG}
 */
ECPointG.prototype._getBeta = function () {
  var pre = this.precomputed
  if (pre && pre.beta) {
    return this.precomputed.beta
  }

  return new ECPoint(this.x.redMul(ecparams.endo.beta), this.y)
}

/*
 * @param {ECPointG[]} points
 * @param {BN[]} coeffs
 * @return {ECPointG}
 */
ECPointG.prototype._endoWnafMulAdd = function (points, coeffs) {
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
 * @param {ECPointG[]} points
 * @param {BN[]} coeffs
 * @param {number} len
 * @return {ECPointG}
 */
ECPointG.prototype._wnafMulAdd = function (points, coeffs, len) {
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

      // hack: ECPointG detection
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
 * @return {{wnd: number, points: ECPointG[]}}
 */
ECPointG.prototype._getNAFPoints = function (wnd) {
  if (this.precomputed) {
    return this.precomputed.naf
  }

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

module.exports = ECPointG
