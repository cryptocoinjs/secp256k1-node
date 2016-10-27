import * as optimized from './optimized'

export default class BN {
  constructor () {
    this.negative = 0
    this.words = null
    this.length = 0
  }

  static fromNumber (n) {
    const bn = new BN()
    bn.words = [n & 0x03ffffff]
    bn.length = 1
    return bn
  }

  static fromBuffer (b32) {
    const bn = new BN()

    bn.words = new Array(10)
    bn.words[0] = (b32[28] & 0x03) << 24 | b32[29] << 16 | b32[30] << 8 | b32[31]
    bn.words[1] = (b32[25] & 0x0F) << 22 | b32[26] << 14 | b32[27] << 6 | b32[28] >>> 2
    bn.words[2] = (b32[22] & 0x3F) << 20 | b32[23] << 12 | b32[24] << 4 | b32[25] >>> 4
    bn.words[3] = (b32[19] & 0xFF) << 18 | b32[20] << 10 | b32[21] << 2 | b32[22] >>> 6

    bn.words[4] = (b32[15] & 0x03) << 24 | b32[16] << 16 | b32[17] << 8 | b32[18]
    bn.words[5] = (b32[12] & 0x0F) << 22 | b32[13] << 14 | b32[14] << 6 | b32[15] >>> 2
    bn.words[6] = (b32[9] & 0x3F) << 20 | b32[10] << 12 | b32[11] << 4 | b32[12] >>> 4
    bn.words[7] = (b32[6] & 0xFF) << 18 | b32[7] << 10 | b32[8] << 2 | b32[9] >>> 6

    bn.words[8] = (b32[2] & 0x03) << 24 | b32[3] << 16 | b32[4] << 8 | b32[5]
    bn.words[9] = b32[0] << 14 | b32[1] << 6 | b32[2] >>> 2

    bn.length = 10
    return bn.strip()
  }

  toBuffer () {
    const w = this.words
    for (let i = this.length; i < 10; ++i) w[i] = 0

    return Buffer.from([
      (w[9] >>> 14) & 0xFF, (w[9] >>> 6) & 0xFF, (w[9] & 0x3F) << 2 | ((w[8] >>> 24) & 0x03), // 0, 1, 2
      (w[8] >>> 16) & 0xFF, (w[8] >>> 8) & 0xFF, w[8] & 0xFF, // 3, 4, 5

      (w[7] >>> 18) & 0xFF, (w[7] >>> 10) & 0xFF, (w[7] >>> 2) & 0xFF, // 6, 7, 8
      ((w[7] & 0x03) << 6) | ((w[6] >>> 20) & 0x3F), (w[6] >>> 12) & 0xFF, (w[6] >>> 4) & 0xFF, // 9, 10, 11
      ((w[6] & 0x0F) << 4) | ((w[5] >>> 22) & 0x0F), (w[5] >>> 14) & 0xFF, (w[5] >>> 6) & 0xFF, // 12, 13, 14
      ((w[5] & 0x3F) << 2) | ((w[4] >>> 24) & 0x03), (w[4] >>> 16) & 0xFF, (w[4] >>> 8) & 0xFF, w[4] & 0xFF, // 15, 16, 17, 18

      (w[3] >>> 18) & 0xFF, (w[3] >>> 10) & 0xFF, (w[3] >>> 2) & 0xFF, // 19, 20, 21
      ((w[3] & 0x03) << 6) | ((w[2] >>> 20) & 0x3F), (w[2] >>> 12) & 0xFF, (w[2] >>> 4) & 0xFF, // 22, 23, 24
      ((w[2] & 0x0F) << 4) | ((w[1] >>> 22) & 0x0F), (w[1] >>> 14) & 0xFF, (w[1] >>> 6) & 0xFF, // 25, 26, 27
      ((w[1] & 0x3F) << 2) | ((w[0] >>> 24) & 0x03), (w[0] >>> 16) & 0xFF, (w[0] >>> 8) & 0xFF, w[0] & 0xFF // 28, 29, 30, 31
    ])
  }

  clone () {
    const r = new BN()
    r.words = new Array(this.length)
    for (let i = 0; i < this.length; i++) r.words[i] = this.words[i]
    r.length = this.length
    r.negative = this.negative
    return r
  }

  strip () {
    while (this.length > 1 && (this.words[this.length - 1] | 0) === 0) this.length--
    return this
  }

  normSign () {
    // -0 = 0
    if (this.length === 1 && this.words[0] === 0) this.negative = 0
    return this
  }

  isEven () {
    return (this.words[0] & 1) === 0
  }

  isOdd () {
    return (this.words[0] & 1) === 1
  }

  isZero () {
    return this.length === 1 && this.words[0] === 0
  }

  ucmp (num) {
    if (this.length !== num.length) return this.length > num.length ? 1 : -1

    for (let i = this.length - 1; i >= 0; --i) {
      if (this.words[i] !== num.words[i]) return this.words[i] > num.words[i] ? 1 : -1
    }

    return 0
  }

  gtOne () {
    return this.length > 1 || this.words[0] > 1
  }

  isOverflow () {
    return this.ucmp(BN.n) >= 0
  }

  isHigh () {
    return this.ucmp(BN.nh) === 1
  }

  bitLengthGT256 () {
    return this.length > 10 || (this.length === 10 && this.words[9] > 0x003fffff)
  }

  iuaddn (num) {
    this.words[0] += num

    let i = 0
    for (; this.words[i] > 0x03ffffff && i < this.length; ++i) {
      this.words[i] -= 0x04000000
      this.words[i + 1] += 1
    }

    if (i === this.length) {
      this.words[i] = 1
      this.length += 1
    }

    return this
  }

  iadd (num) {
    // (-this) + num -> -(this - num)
    // this + (-num) -> this - num
    if (this.negative !== num.negative) {
      if (this.negative !== 0) {
        this.negative = 0
        this.isub(num)
        this.negative ^= 1
      } else {
        num.negative = 0
        this.isub(num)
        num.negative = 1
      }

      return this.normSign()
    }

    // a.length > b.length
    let a
    let b
    if (this.length > num.length) {
      a = this
      b = num
    } else {
      a = num
      b = this
    }

    let i = 0
    let carry = 0
    for (; i < b.length; ++i) {
      var word = a.words[i] + b.words[i] + carry
      this.words[i] = word & 0x03ffffff
      carry = word >>> 26
    }

    for (; carry !== 0 && i < a.length; ++i) {
      word = a.words[i] + carry
      this.words[i] = word & 0x03ffffff
      carry = word >>> 26
    }

    this.length = a.length
    if (carry !== 0) {
      this.words[this.length++] = carry
    } else if (a !== this) {
      for (; i < a.length; ++i) {
        this.words[i] = a.words[i]
      }
    }

    return this
  }

  add (num) {
    return this.clone().iadd(num)
  }

  isub (num) {
    // (-this) - num -> -(this + num)
    // this - (-num) -> this + num
    if (this.negative !== num.negative) {
      if (this.negative !== 0) {
        this.negative = 0
        this.iadd(num)
        this.negative = 1
      } else {
        num.negative = 0
        this.iadd(num)
        num.negative = 1
      }

      return this.normSign()
    }

    const cmp = this.ucmp(num)
    if (cmp === 0) {
      this.negative = 0
      this.words[0] = 0
      this.length = 1
      return this
    }

    // a > b
    let a
    let b
    if (cmp > 0) {
      a = this
      b = num
    } else {
      a = num
      b = this
    }

    let i = 0
    let carry = 0
    for (; i < b.length; ++i) {
      const word = a.words[i] - b.words[i] + carry
      carry = word >> 26
      this.words[i] = word & 0x03ffffff
    }

    for (; carry !== 0 && i < a.length; ++i) {
      const word = a.words[i] + carry
      carry = word >> 26
      this.words[i] = word & 0x03ffffff
    }

    if (carry === 0 && i < a.length && a !== this) {
      for (; i < a.length; ++i) this.words[i] = a.words[i]
    }

    this.length = Math.max(this.length, i)

    if (a !== this) this.negative ^= 1

    return this.strip().normSign()
  }

  sub (num) {
    return this.clone().isub(num)
  }

  static umulTo (num1, num2, out) {
    out.length = num1.length + num2.length - 1

    const a1 = num1.words[0]
    const b1 = num2.words[0]
    const r1 = a1 * b1

    let carry = (r1 / 0x04000000) | 0
    out.words[0] = r1 & 0x03ffffff

    for (let k = 1, maxK = out.length; k < maxK; k++) {
      let ncarry = carry >>> 26
      let rword = carry & 0x03ffffff
      for (let j = Math.max(0, k - num1.length + 1), maxJ = Math.min(k, num2.length - 1); j <= maxJ; j++) {
        const i = k - j
        const a = num1.words[i]
        const b = num2.words[j]
        const r = a * b + rword
        ncarry += (r / 0x04000000) | 0
        rword = r & 0x03ffffff
      }
      out.words[k] = rword
      carry = ncarry
    }

    if (carry !== 0) out.words[out.length++] = carry

    return out.strip()
  }

  static umulTo10x10 = Math.imul ? optimized.umulTo10x10 : BN.umulTo

  static umulnTo (num, k, out) {
    if (k === 0) {
      out.words = [0]
      out.length = 1
      return out
    }

    let i = 0
    let carry = 0
    for (; i < num.length; ++i) {
      var r = num.words[i] * k + carry
      out.words[i] = r & 0x03ffffff
      carry = (r / 0x04000000) | 0
    }

    if (carry > 0) {
      out.words[i] = carry
      out.length = num.length + 1
    } else {
      out.length = num.length
    }

    return out
  }

  umul (num) {
    const out = new BN()
    out.words = new Array(this.length + num.length)

    if (this.length === 10 && num.length === 10) {
      return BN.umulTo10x10(this, num, out)
    } else if (this.length === 1) {
      return BN.umulnTo(num, this.words[0], out)
    } else if (num.length === 1) {
      return BN.umulnTo(this, num.words[0], out)
    } else {
      return BN.umulTo(this, num, out)
    }
  }

  isplit (output) {
    output.length = Math.min(this.length, 9)
    for (let i = 0; i < output.length; ++i) output.words[i] = this.words[i]

    if (this.length <= 9) {
      this.words[0] = 0
      this.length = 1
      return this
    }

    // Shift by 9 limbs
    let prev = this.words[9]
    output.words[output.length++] = prev & 0x003fffff

    let j = 10
    for (; j < this.length; ++j) {
      var word = this.words[j]
      this.words[j - 10] = ((word & 0x003fffff) << 4) | (prev >>> 22)
      prev = word
    }
    prev >>>= 22
    this.words[j - 10] = prev

    if (prev === 0 && this.length > 10) {
      this.length -= 10
    } else {
      this.length -= 9
    }

    return this
  }

  fireduce () {
    if (this.isOverflow()) this.isub(BN.n)
    return this
  }

  ureduce () {
    let num = this.clone().isplit(bnTmp).umul(BN.nc).iadd(bnTmp)
    if (num.bitLengthGT256()) {
      num = num.isplit(bnTmp).umul(BN.nc).iadd(bnTmp)
      if (num.bitLengthGT256()) num = num.isplit(bnTmp).umul(BN.nc).iadd(bnTmp)
    }

    return num.fireduce()
  }

  ishrn (n) {
    const mask = (1 << n) - 1
    const m = 26 - n

    for (let i = this.length - 1, carry = 0; i >= 0; --i) {
      const word = this.words[i]
      this.words[i] = (carry << m) | (word >>> n)
      carry = word & mask
    }

    if (this.length > 1 && this.words[this.length - 1] === 0) this.length -= 1

    return this
  }

  uinvm () {
    const x = this.clone()
    const y = BN.n.clone()

    // A * x + B * y = x
    const A = BN.fromNumber(1)
    const B = BN.fromNumber(0)

    // C * x + D * y = y
    const C = BN.fromNumber(0)
    const D = BN.fromNumber(1)

    while (x.isEven() && y.isEven()) {
      let k = 1
      for (let m = 1; (x.words[0] & m) === 0 && (y.words[0] & m) === 0 && k < 26; ++k, m <<= 1);
      x.ishrn(k)
      y.ishrn(k)
    }

    const yp = y.clone()
    const xp = x.clone()

    while (!x.isZero()) {
      let i = 0
      for (let im = 1; (x.words[0] & im) === 0 && i < 26; ++i, im <<= 1);
      if (i > 0) {
        x.ishrn(i)
        while (i-- > 0) {
          if (A.isOdd() || B.isOdd()) {
            A.iadd(yp)
            B.isub(xp)
          }

          A.ishrn(1)
          B.ishrn(1)
        }
      }

      let j = 0
      for (let jm = 1; (y.words[0] & jm) === 0 && j < 26; ++j, jm <<= 1);
      if (j > 0) {
        y.ishrn(j)
        while (j-- > 0) {
          if (C.isOdd() || D.isOdd()) {
            C.iadd(yp)
            D.isub(xp)
          }

          C.ishrn(1)
          D.ishrn(1)
        }
      }

      if (x.ucmp(y) >= 0) {
        x.isub(y)
        A.isub(C)
        B.isub(D)
      } else {
        y.isub(x)
        C.isub(A)
        D.isub(B)
      }
    }

    if (C.negative === 1) {
      C.negative = 0
      const result = C.ureduce()
      result.negative ^= 1
      return result.normSign().iadd(BN.n)
    } else {
      return C.ureduce()
    }
  }

  imulK () {
    this.words[this.length] = 0
    this.words[this.length + 1] = 0
    this.length += 2

    for (let i = 0, lo = 0; i < this.length; ++i) {
      const w = this.words[i] | 0
      lo += w * 0x3d1
      this.words[i] = lo & 0x03ffffff
      lo = w * 0x40 + ((lo / 0x04000000) | 0)
    }

    if (this.words[this.length - 1] === 0) {
      this.length -= 1
      if (this.words[this.length - 1] === 0) this.length -= 1
    }

    return this
  }

  redIReduce () {
    this.isplit(bnTmp).imulK().iadd(bnTmp)
    if (this.bitLengthGT256()) this.isplit(bnTmp).imulK().iadd(bnTmp)

    const cmp = this.ucmp(BN.p)
    if (cmp === 0) {
      this.words[0] = 0
      this.length = 1
    } else if (cmp > 0) {
      this.isub(BN.p)
    } else {
      this.strip()
    }

    return this
  }

  redNeg () {
    if (this.isZero()) return BN.fromNumber(0)

    return BN.p.sub(this)
  }

  redAdd (num) {
    return this.clone().redIAdd(num)
  }

  redIAdd (num) {
    this.iadd(num)
    if (this.ucmp(BN.p) >= 0) this.isub(BN.p)

    return this
  }

  redIAdd7 () {
    this.iuaddn(7)
    if (this.ucmp(BN.p) >= 0) this.isub(BN.p)

    return this
  }

  redSub (num) {
    return this.clone().redISub(num)
  }

  redISub (num) {
    this.isub(num)
    if (this.negative !== 0) this.iadd(BN.p)

    return this
  }

  redMul (num) {
    return this.umul(num).redIReduce()
  }

  redSqr () {
    return this.umul(this).redIReduce()
  }

  redSqrt () {
    if (this.isZero()) return this.clone()

    const wv2 = this.redSqr()
    const wv4 = wv2.redSqr()
    const wv12 = wv4.redSqr().redMul(wv4)
    const wv14 = wv12.redMul(wv2)
    const wv15 = wv14.redMul(this)

    let out = wv15
    for (let i = 0; i < 54; ++i) out = out.redSqr().redSqr().redSqr().redSqr().redMul(wv15)
    out = out.redSqr().redSqr().redSqr().redSqr().redMul(wv14)
    for (let i = 0; i < 5; ++i) out = out.redSqr().redSqr().redSqr().redSqr().redMul(wv15)
    out = out.redSqr().redSqr().redSqr().redSqr().redMul(wv12)
    out = out.redSqr().redSqr().redSqr().redSqr().redSqr().redSqr().redMul(wv12)

    if (out.redSqr().ucmp(this) === 0) {
      return out
    } else {
      return null
    }
  }

  redInvm () {
    const a = this.clone()
    const b = BN.p.clone()

    const x1 = BN.fromNumber(1)
    const x2 = BN.fromNumber(0)

    while (a.gtOne() && b.gtOne()) {
      let i = 0
      for (let im = 1; (a.words[0] & im) === 0 && i < 26; ++i, im <<= 1);
      if (i > 0) {
        a.ishrn(i)
        while (i-- > 0) {
          if (x1.isOdd()) x1.iadd(BN.p)
          x1.ishrn(1)
        }
      }

      let j = 0
      for (let jm = 1; (b.words[0] & jm) === 0 && j < 26; ++j, jm <<= 1);
      if (j > 0) {
        b.ishrn(j)
        while (j-- > 0) {
          if (x2.isOdd()) x2.iadd(BN.p)
          x2.ishrn(1)
        }
      }

      if (a.ucmp(b) >= 0) {
        a.isub(b)
        x1.isub(x2)
      } else {
        b.isub(a)
        x2.isub(x1)
      }
    }

    let res
    if (a.length === 1 && a.words[0] === 1) {
      res = x1
    } else {
      res = x2
    }

    if (res.negative !== 0) res.iadd(BN.p)

    if (res.negative !== 0) {
      res.negative = 0
      return res.redIReduce().redNeg()
    } else {
      return res.redIReduce()
    }
  }

  getNAF (w) {
    const naf = []
    const ws = 1 << (w + 1)
    const wsm1 = ws - 1
    const ws2 = ws >> 1

    const k = this.clone()
    while (!k.isZero()) {
      let i = 0
      for (let m = 1; (k.words[0] & m) === 0 && i < 26; ++i, m <<= 1) naf.push(0)

      if (i !== 0) {
        k.ishrn(i)
      } else {
        const mod = k.words[0] & wsm1
        if (mod >= ws2) {
          naf.push(ws2 - mod)
          k.iuaddn(mod - ws2).ishrn(1)
        } else {
          naf.push(mod)
          k.words[0] -= mod
          if (!k.isZero()) {
            for (i = w - 1; i > 0; --i) naf.push(0)
            k.ishrn(w)
          }
        }
      }
    }

    return naf
  }

  inspect () {
    if (this.isZero()) return '0'

    const buffer = this.toBuffer().toString('hex')
    let i = 0
    for (; buffer[i] === '0'; ++i);
    return buffer.slice(i)
  }

  static n = BN.fromBuffer(Buffer.from('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 'hex'))
  static nh = BN.n.clone().ishrn(1)
  static nc = BN.fromBuffer(Buffer.from('000000000000000000000000000000014551231950B75FC4402DA1732FC9BEBF', 'hex'))
  static p = BN.fromBuffer(Buffer.from('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 'hex'))
  static psn = BN.p.sub(BN.n)
}

const bnTmp = new BN()
bnTmp.words = new Array(10)

// WTF?! it speed-up benchmark on ~20%
;(() => {
  const x = BN.fromNumber(1)
  x.words[3] = 0
})()
