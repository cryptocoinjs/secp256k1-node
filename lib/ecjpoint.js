'use strict'


/**
 * @class ECJPoint
 * @constructor
 * @param {BN} x
 * @param {BN} y
 * @param {BN} z
 */
function ECJPoint (x, y, z) {
  if (x === null && y === null && z === null) {
    this.x = ECJPoint.one
    this.y = ECJPoint.one
    this.z = ECJPoint.zero
  } else {
    this.x = x
    this.y = y
    this.z = z
  }

  this.zOne = this.z.cmp(ECJPoint.one) === 0
}

/**
 * @return {ECPoint}
 */
ECJPoint.prototype.toECPoint = function () {
  var ECPoint = require('./ecpoint')

  if (this.isInfinity()) {
    return new ECPoint(null, null)
  }

  var zinv = this.z.redInvm()
  var zinv2 = zinv.redSqr()
  var ax = this.x.redMul(zinv2)
  var ay = this.y.redMul(zinv2).redMul(zinv)

  return new ECPoint(ax, ay)
}

/**
 * @param {ECPoint} p
 * @return {ECJPoint}
 */
ECJPoint.prototype.mixedAdd = function (p) {
  // O + P = P
  if (this.isInfinity()) {
    return p.toECJPoint()
  }

  // P + O = P
  if (p.isInfinity()) {
    return this
  }

  // 8M + 3S + 7A
  var z2 = this.z.redSqr()
  var u1 = this.x
  var u2 = p.x.redMul(z2)
  var s1 = this.y
  var s2 = p.y.redMul(z2).redIMul(this.z)

  var h = u1.redSub(u2)
  var r = s1.redSub(s2)
  if (h.cmpn(0) === 0) {
    if (r.cmpn(0) === 0) {
      return this.dbl()
    }

    return new ECJPoint(null, null, null)
  }

  var h2 = h.redSqr()
  var h3 = h2.redMul(h)
  var v = u1.redIMul(h2)

  var nx = r.redSqr().redIAdd(h3).redISub(v).redISub(v)
  var ny = r.redMul(v.redISub(nx)).redISub(s1.redIMul(h3))
  var nz = this.z.redMul(h)

  return new ECJPoint(nx, ny, nz)
}

/**
 * @param {number} pow
 * @return {ECJPoint}
 */
ECJPoint.prototype.dblp = function (pow) {
  if (pow === 0 || this.isInfinity()) {
    return this
  }

  var result = this
  for (var i = 0; i < pow; i++) {
    result = result.dbl()
  }

  return result
}

/**
 * @return {ECJPoint}
 */
ECJPoint.prototype.dbl = function () {
  if (this.isInfinity()) {
    return this
  }

  var nx
  var ny
  var nz
  // Z = 1
  if (this.zOne) {
    // hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html
    //     #doubling-mdbl-2007-bl
    // 1M + 5S + 14A

    // XX = X1^2
    var xx = this.x.redSqr()
    // YY = Y1^2
    var yy = this.y.redSqr()
    // YYYY = YY^2
    var yyyy = yy.redSqr()
    // S = 2 * ((X1 + YY)^2 - XX - YYYY)
    var s = this.x.redAdd(yy).redISqr().redISub(xx).redISub(yyyy)
    s = s.redIAdd(s)
    // M = 3 * XX + a; a = 0
    var m = xx.redAdd(xx).redIAdd(xx)
    // T = M ^ 2 - 2*S
    var t = m.redSqr().redISub(s).redISub(s)

    // 8 * YYYY
    var yyyy8 = yyyy.redIAdd(yyyy)
    yyyy8 = yyyy8.redIAdd(yyyy8)
    yyyy8 = yyyy8.redIAdd(yyyy8)

    // X3 = T
    nx = t
    // Y3 = M * (S - T) - 8 * YYYY
    ny = m.redIMul(s.redISub(t)).redISub(yyyy8)
    // Z3 = 2*Y1
    nz = this.y.redAdd(this.y)
  } else {
    // hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html
    //     #doubling-dbl-2009-l
    // 2M + 5S + 13A

    // A = X1^2
    var a = this.x.redSqr()
    // B = Y1^2
    var b = this.y.redSqr()
    // C = B^2
    var c = b.redSqr()
    // D = 2 * ((X1 + B)^2 - A - C)
    var d = this.x.redAdd(b).redISqr().redISub(a).redISub(c)
    d = d.redIAdd(d)
    // E = 3 * A
    var e = a.redAdd(a).redIAdd(a)
    // F = E^2
    var f = e.redSqr()

    // 8 * C
    var c8 = c.redIAdd(c)
    c8 = c8.redIAdd(c8)
    c8 = c8.redIAdd(c8)

    // X3 = F - 2 * D
    nx = f.redISub(d).redISub(d)
    // Y3 = E * (D - X3) - 8 * C
    ny = e.redIMul(d.redISub(nx)).redISub(c8)
    // Z3 = 2 * Y1 * Z1
    nz = this.y.redMul(this.z)
    nz = nz.redIAdd(nz)
  }

  return new ECJPoint(nx, ny, nz)
}

/**
 * @return {boolean}
 */
ECJPoint.prototype.isInfinity = function () {
  return this.z.cmpn(0) === 0
}

module.exports = ECJPoint
