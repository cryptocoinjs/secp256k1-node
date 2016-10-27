import BN from './bn'
import ECJPoint from './ecjpoint'

export default class ECPoint {
  constructor (x, y) {
    if (x === null && y === null) {
      this.x = this.y = null
      this.inf = true
    } else {
      this.x = x
      this.y = y
      this.inf = false
    }
  }

  static fromPublicKey (publicKey) {
    var first = publicKey[0]
    var x
    var y

    if (publicKey.length === 33 && (first === 0x02 || first === 0x03)) {
      x = BN.fromBuffer(publicKey.slice(1, 33))

      // overflow
      if (x.ucmp(BN.p) >= 0) return null

      // create from X
      y = x.redSqr().redMul(x).redIAdd7().redSqrt()
      if (y === null) return null
      if ((first === 0x03) !== y.isOdd()) y = y.redNeg()

      return new ECPoint(x, y)
    }

    if (publicKey.length === 65 && (first === 0x04 || first === 0x06 || first === 0x07)) {
      x = BN.fromBuffer(publicKey.slice(1, 33))
      y = BN.fromBuffer(publicKey.slice(33, 65))

      // overflow
      if (x.ucmp(BN.p) >= 0 || y.ucmp(BN.p) >= 0) return null

      // is odd flag
      if ((first === 0x06 || first === 0x07) && y.isOdd() !== (first === 0x07)) return null

      // x*x*x + 7 = y*y
      if (x.redSqr().redMul(x).redIAdd7().ucmp(y.redSqr()) !== 0) return null

      return new ECPoint(x, y)
    }

    return null
  }

  toPublicKey (compressed) {
    const x = this.x
    const y = this.y
    let publicKey

    if (compressed) {
      publicKey = Buffer.allocUnsafe(33)
      publicKey[0] = y.isOdd() ? 0x03 : 0x02
      x.toBuffer().copy(publicKey, 1)
    } else {
      publicKey = Buffer.allocUnsafe(65)
      publicKey[0] = 0x04
      x.toBuffer().copy(publicKey, 1)
      y.toBuffer().copy(publicKey, 33)
    }

    return publicKey
  }

  static fromECJPoint (p) {
    if (p.inf) return new ECPoint(null, null)

    const zinv = p.z.redInvm()
    const zinv2 = zinv.redSqr()
    const ax = p.x.redMul(zinv2)
    const ay = p.y.redMul(zinv2).redMul(zinv)

    return new ECPoint(ax, ay)
  }

  toECJPoint () {
    if (this.inf) return new ECJPoint(null, null, null)
    return new ECJPoint(this.x, this.y, ECJPoint.one)
  }

  neg () {
    if (this.inf) return this
    return new ECPoint(this.x, this.y.redNeg())
  }

  add (p) {
    // O + P = P
    if (this.inf) return p

    // P + O = P
    if (p.inf) return this

    if (this.x.ucmp(p.x) === 0) {
      // P + P = 2P
      if (this.y.ucmp(p.y) === 0) return this.dbl()
      // P + (-P) = O
      return new ECPoint(null, null)
    }

    // s = (y - yp) / (x - xp)
    // nx = s^2 - x - xp
    // ny = s * (x - nx) - y
    let s = this.y.redSub(p.y)
    if (!s.isZero()) s = s.redMul(this.x.redSub(p.x).redInvm())

    const nx = s.redSqr().redISub(this.x).redISub(p.x)
    const ny = s.redMul(this.x.redSub(nx)).redISub(this.y)
    return new ECPoint(nx, ny)
  }

  dbl () {
    if (this.inf) return this

    // 2P = O
    const yy = this.y.redAdd(this.y)
    if (yy.isZero()) return new ECPoint(null, null)

    // s = (3 * x^2) / (2 * y)
    // nx = s^2 - 2*x
    // ny = s * (x - nx) - y
    const x2 = this.x.redSqr()
    const s = x2.redAdd(x2).redIAdd(x2).redMul(yy.redInvm())

    const nx = s.redSqr().redISub(this.x.redAdd(this.x))
    const ny = s.redMul(this.x.redSub(nx)).redISub(this.y)
    return new ECPoint(nx, ny)
  }

  mul (num) {
    // Algorithm 3.36 Window NAF method for point multiplication
    const nafPoints = this._getNAFPoints(4)
    const points = nafPoints.points

    // Get NAF form
    const naf = num.getNAF(nafPoints.wnd)

    // Add `this`*(N+1) for every w-NAF index
    let acc = new ECJPoint(null, null, null)
    for (let i = naf.length - 1; i >= 0; i--) {
      // Count zeroes
      let k = 0
      for (; i >= 0 && naf[i] === 0; i--, ++k);
      if (i >= 0) k += 1
      acc = acc.dblp(k)

      if (i < 0) break

      // J +- P
      const z = naf[i]
      if (z > 0) {
        acc = acc.mixedAdd(points[(z - 1) >> 1])
      } else {
        acc = acc.mixedAdd(points[(-z - 1) >> 1].neg())
      }
    }

    return ECPoint.fromECJPoint(acc)
  }

  _getNAFPoints1 () {
    return { wnd: 1, points: [this] }
  }

  _getNAFPoints (wnd) {
    const points = new Array((1 << wnd) - 1)
    points[0] = this
    const dbl = this.dbl()
    for (let i = 1; i < points.length; ++i) points[i] = points[i - 1].add(dbl)
    return { wnd: wnd, points: points }
  }
}
