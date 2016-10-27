import BN from './bn'
import ECPoint from './ecpoint'
import ECJPoint from './ecjpoint'

class ECPointG {
  constructor () {
    this.x = BN.fromBuffer(Buffer.from('79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798', 'hex'))
    this.y = BN.fromBuffer(Buffer.from('483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8', 'hex'))
    this.inf = false

    this._precompute()
  }

  _precompute () {
    const ecpoint = new ECPoint(this.x, this.y)

    const dstep = 4
    const points = new Array(1 + Math.ceil(257 / dstep))
    let acc = points[0] = ecpoint
    for (let i = 1; i < points.length; ++i) {
      for (let j = 0; j < dstep; j++) acc = acc.dbl()
      points[i] = acc
    }

    this.precomputed = {
      naf: ecpoint._getNAFPoints(7),
      doubles: {
        step: dstep,
        points: points,
        negpoints: points.map((p) => p.neg())
      }
    }
  }

  mul (num) {
    // Algorithm 3.42 Fixed-base NAF windowing method for point multiplication
    const step = this.precomputed.doubles.step
    const points = this.precomputed.doubles.points
    const negpoints = this.precomputed.doubles.negpoints

    const naf = num.getNAF(1)
    const I = ((1 << (step + 1)) - (step % 2 === 0 ? 2 : 1)) / 3

    // Translate into more windowed form
    let repr = []
    for (let j = 0; j < naf.length; j += step) {
      let nafW = 0
      for (let k = j + step - 1; k >= j; k--) nafW = (nafW << 1) + naf[k]
      repr.push(nafW)
    }

    let a = new ECJPoint(null, null, null)
    let b = new ECJPoint(null, null, null)
    for (let i = I; i > 0; i--) {
      for (let jj = 0; jj < repr.length; jj++) {
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

  mulAdd (k1, p2, k2) {
    const nafPointsP1 = this.precomputed.naf
    const nafPointsP2 = p2._getNAFPoints1()
    const wnd = [nafPointsP1.points, nafPointsP2.points]
    const naf = [k1.getNAF(nafPointsP1.wnd), k2.getNAF(nafPointsP2.wnd)]

    let acc = new ECJPoint(null, null, null)
    const tmp = [null, null]
    for (let i = Math.max(naf[0].length, naf[1].length); i >= 0; i--) {
      let k = 0
      for (; i >= 0; ++k, --i) {
        tmp[0] = naf[0][i] | 0
        tmp[1] = naf[1][i] | 0

        if (tmp[0] !== 0 || tmp[1] !== 0) break
      }

      if (i >= 0) k += 1
      acc = acc.dblp(k)

      if (i < 0) break

      for (let jj = 0; jj < 2; jj++) {
        const z = tmp[jj]
        let p
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

    return acc
  }
}

export default new ECPointG()
