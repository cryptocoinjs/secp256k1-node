'use strict'

var inherits = require('inherits')

var ECPoint = require('./ecpoint')
var ECJPoint = require('./ecjpoint')
var util = require('./util')

/**
 * @class ECPointG
 * @extends ECPoint
 * @constructor
 * @param {BN} gx
 * @param {BN} gy
 */
function ECPointG (gx, gy) {
  ECPoint.call(this, gx, gy)

  this.precomputed = {
    doubles: this._getDoubles(4),
    naf: ECPoint.prototype._getNAFPoints.call(this, 8)
  }
}

inherits(ECPointG, ECPoint)

/**
 * @param {BN} num
 * @return {ECPointG}
 */
ECPointG.prototype.mul = function (num) {
  // Algorithm 3.42 Fixed-base NAF windowing method for point multiplication
  var step = this.precomputed.doubles.step
  var points = this.precomputed.doubles.points
  var negpoints = this.precomputed.doubles.negpoints

  var naf = util.getNAF(num, 1)
  var I = ((1 << (step + 1)) - (step % 2 === 0 ? 2 : 1)) / 3

  // Translate into more windowed form
  var repr = []
  for (var j = 0; j < naf.length; j += step) {
    var nafW = 0
    for (var k = j + step - 1; k >= j; k--) {
      nafW = (nafW << 1) + naf[k]
    }

    repr.push(nafW)
  }

  var a = new ECJPoint(null, null, null)
  var b = new ECJPoint(null, null, null)
  for (var i = I; i > 0; i--) {
    for (var jj = 0; jj < repr.length; jj++) {
      if (repr[jj] === i) {
        b = b.mixedAdd(points[jj])
      } else if (repr[jj] === -i) {
        b = b.mixedAdd(negpoints[jj])
      }
    }

    a = a.add(b)
  }

  return ECPoint.fromECJPoint(a)
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
 * @return {{wnd: number, points: ECPointG[]}}
 */
ECPointG.prototype._getNAFPoints = function () {
  return this.precomputed.naf
}

module.exports = ECPointG
