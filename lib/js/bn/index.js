'use strict'

var optimized = require('./optimized')

/**
 * @class BN
 */
function BN () {
  this.negative = 0
  this.words = null
  this.length = 0
}

/**
 * @param {Buffer} b32
 * @return {BN}
 */
BN.fromBuffer = function (b32) {
  var bn = new BN()

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

/**
 * @param {number} n
 * @return {BN}
 */
BN.fromNumber = function (n) {
  var bn = new BN()
  bn.words = [n]
  bn.length = 1
  return bn
}

/**
 * @return {Buffer}
 */
BN.prototype.toBuffer = function () {
  var w = this.words
  return new Buffer([
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

/**
 * @return {BN}
 */
BN.prototype.clone = function () {
  var r = new BN()
  r.words = new Array(this.length)
  for (var i = 0; i < this.length; i++) {
    r.words[i] = this.words[i]
  }
  r.length = this.length
  r.negative = this.negative
  return r
}

/**
 * @return {BN}
 */
BN.prototype.strip = function () {
  while (this.length > 1 && this.words[this.length - 1] === 0) {
    this.length--
  }

  return this._normSign()
}

/**
 * @return {BN}
 */
BN.prototype._normSign = function () {
  // -0 = 0
  if (this.length === 1 && this.words[0] === 0) {
    this.negative = 0
  }

  return this
}

/**
 * @param {number} num
 * @return {BN}
 */
BN.prototype._iuaddn = function (num) {
  this.words[0] += num

  for (var i = 0; this.words[i] > 0x03ffffff && i < this.length; ++i) {
    this.words[i] -= 0x04000000
    this.words[i + 1] += 1
  }

  if (i === this.length) {
    this.words[i] = 1
    this.length += 1
  }

  return this
}

/**
 * @param {BN} num
 * @return {BN}
 */
BN.prototype.iadd = function (num) {
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

    return this._normSign()
  }

  // a.length > b.length
  var a
  var b
  if (this.length > num.length) {
    a = this
    b = num
  } else {
    a = num
    b = this
  }

  for (var i = 0, carry = 0; i < b.length; ++i) {
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

/**
 * @param {BN} num
 * @return {BN}
 */
BN.prototype.add = function (num) {
  return this.clone().iadd(num)
}

/**
 * @param {BN} num
 * @return {BN}
 */
BN.prototype.isub = function (num) {
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

    return this._normSign()
  }

  var cmp = this.ucmp(num)
  if (cmp === 0) {
    this.negative = 0
    this.words[0] = 0
    this.length = 1
    return this
  }

  // a > b
  var a
  var b
  if (cmp > 0) {
    a = this
    b = num
  } else {
    a = num
    b = this
  }

  for (var i = 0, carry = 0; i < b.length; ++i) {
    var word = a.words[i] - b.words[i] + carry
    carry = word >> 26
    this.words[i] = word & 0x03ffffff
  }

  for (; carry !== 0 && i < a.length; ++i) {
    word = a.words[i] + carry
    carry = word >> 26
    this.words[i] = word & 0x03ffffff
  }

  if (carry === 0 && i < a.length && a !== this) {
    for (; i < a.length; ++i) {
      this.words[i] = a.words[i]
    }
  }

  this.length = Math.max(this.length, i)

  if (a !== this) {
    this.negative ^= 1
  }

  return this.strip()
}

/**
 * @param {BN} num
 * @return {BN}
 */
BN.prototype.sub = function (num) {
  return this.clone().isub(num)
}

/**
 * @param {BN} num1
 * @param {BN} num2
 * @param {BN} out
 */
BN._umulTo = function (num1, num2, out) {
  out.length = num1.length + num2.length

  var a1 = num1.words[0]
  var b1 = num2.words[0]
  var r1 = a1 * b1

  var carry = (r1 / 0x04000000) | 0
  out.words[0] = r1 & 0x03ffffff

  for (var k = 1, maxK = out.length - 1; k < maxK; k++) {
    var ncarry = carry >>> 26
    var rword = carry & 0x03ffffff
    for (var j = Math.max(0, k - num1.length + 1), maxJ = Math.min(k, num2.length - 1); j <= maxJ; j++) {
      var i = k - j
      var a = num1.words[i]
      var b = num2.words[j]
      var r = a * b + rword
      ncarry += (r / 0x04000000) | 0
      rword = r & 0x03ffffff
    }
    out.words[k] = rword
    carry = ncarry
  }

  if (carry !== 0) {
    out.words[k] = carry
  } else {
    out.length -= 1
  }

  return out.strip()
}

BN._umulTo10x10 = Math.imul ? optimized.umulTo10x10 : BN._umulTo

/**
 * @param {BN} num
 * @param {BN} out
 */
BN.prototype._umulTo = function (num, out) {
  // TODO: add 1 and 10
  if (this.length === 10 && num.length === 10) {
    return BN._umulTo10x10(this, num, out)
  } else {
    return BN._umulTo(this, num, out)
  }
}

/**
 * @param {BN} num
 * @return {BN}
 */
BN.prototype.umul = function (num) {
  var out = new BN()
  out.words = new Array(this.length + num.length)
  return this._umulTo(num, out)
}

/**
 * @return {BN}
 */
BN.prototype.iushl4 = function () {
  for (var i = 0, carry = 0; i < this.length; ++i) {
    var newCarry = this.words[i] & 0x03c00000
    var c = (this.words[i] - newCarry) << 4
    this.words[i] = c | carry
    carry = newCarry >>> 22
  }

  if (carry) {
    this.words[i] = carry
    this.length += 1
  }

  return this
}

/**
 * @param {number} n
 * @return {BN}
 */
BN.prototype.iushrn = function (n) {
  var mask = (1 << n) - 1
  var m = 26 - n

  for (var i = this.length - 1, carry = 0; i >= 0; --i) {
    var word = this.words[i]
    this.words[i] = (carry << m) | (word >>> n)
    carry = word & mask
  }

  if (this.length > 1 && this.words[this.length - 1] === 0) {
    this.length -= 1
  }

  return this
}

/**
 * @param {BN} num
 * @param {number} mul
 * @param {number} shift
 * @return {BN}
 */
BN.prototype._ishlnsubmul = function (num, mul, shift) {
  var len = num.length + shift
  if (len > this.length) {
    for (var j = this.length; j < len; ++j) {
      this.words[j] = 0
    }

    this.length = len
  }

  for (var i = 0, carry = 0, w; i < num.length; ++i) {
    w = this.words[i + shift] + carry
    var right = num.words[i] * mul
    w -= right & 0x03ffffff
    carry = (w >> 26) - ((right / 0x04000000) | 0)
    this.words[i + shift] = w & 0x03ffffff
  }

  for (; i < this.length - shift; ++i) {
    w = this.words[i + shift] + carry
    carry = w >> 26
    this.words[i + shift] = w & 0x03ffffff
  }

  if (carry !== 0) {
    // assert(carry === -1)
    carry = 0
    for (i = 0; i < this.length; ++i) {
      w = carry - this.words[i]
      carry = w >> 26
      this.words[i] = w & 0x3ffffff
    }
    this.negative = 1
  }

  return this.strip()
}

BN.prototype.reduce = function () {
  if (this.negative !== 0) {
    this.negative = 0
    var result = this.reduce()
    this.negative = 1
    result.negative ^= 1
    return result._normSign().iadd(BN.n)
  }

  if (this.ucmp(BN.n) === -1 || this.isZero()) {
    return this.clone()
  }

  var a = this.clone().iushl4()
  var b = BN._reduceDevisor.clone()
  var bhi = b.words[b.length - 1]

  var m = a.length - b.length
  var diff = a.clone()._ishlnsubmul(b, 1, m)
  if (diff.negative === 0) {
    a = diff
  }

  for (var j = m - 1; j >= 0; --j) {
    var qji = b.length + j
    var qj = a.words[qji] * 0x04000000 + a.words[qji - 1]
    qj = Math.min((qj / bhi) | 0, 0x03ffffff)

    a._ishlnsubmul(b, qj, j)
    while (a.negative !== 0) {
      qj -= 1
      a.negative = 0
      a._ishlnsubmul(b, 1, j)
      if (!a.isZero()) {
        a.negative ^= 1
      }
    }
  }

  return a.strip().iushrn(4)
}

BN.prototype.invm = function () {
  var x = this
  var y = BN.n.clone()

  if (x.negative !== 0) {
    x = x.reduce()
  } else {
    x = x.clone()
  }

  // A * x + B * y = x
  var A = BN.fromNumber(1)
  var B = BN.fromNumber(0)

  // C * x + D * y = y
  var C = BN.fromNumber(0)
  var D = BN.fromNumber(1)

  var g = 0

  while (x.isEven() && y.isEven()) {
    x.iushrn(1)
    y.iushrn(1)
    ++g
  }

  var yp = y.clone()
  var xp = x.clone()

  while (!x.isZero()) {
    for (var i = 0, im = 1; (x.words[0] & im) === 0 && i < 26; ++i, im <<= 1);
    if (i > 0) {
      x.iushrn(i)
      while (i-- > 0) {
        if (A.isOdd() || B.isOdd()) {
          A.iadd(yp)
          B.isub(xp)
        }

        A.iushrn(1)
        B.iushrn(1)
      }
    }

    for (var j = 0, jm = 1; (y.words[0] & jm) === 0 && j < 26; ++j, jm <<= 1);
    if (j > 0) {
      y.iushrn(j)
      while (j-- > 0) {
        if (C.isOdd() || D.isOdd()) {
          C.iadd(yp)
          D.isub(xp)
        }

        C.iushrn(1)
        D.iushrn(1)
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

  return C.reduce()
}

/**
 * @return {boolean}
 */
BN.prototype.isEven = function () {
  return (this.words[0] & 1) === 0
}

/**
 * @return {boolean}
 */
BN.prototype.isOdd = function () {
  return (this.words[0] & 1) === 1
}

/**
 * @return {boolean}
 */
BN.prototype.isZero = function () {
  return this.length === 1 && this.words[0] === 0
}

/**
 * @return {boolean}
 */
BN.prototype.gtOne = function () {
  return this.length > 1 || this.words[0] > 1
}

/**
 * @return {boolean}
 */
BN.prototype.isOverflow = function () {
  return this.ucmp(BN.n) >= 0
}

/**
 * @return {boolean}
 */
BN.prototype.isHigh = function () {
  return this.ucmp(BN.nh) === 1
}

/**
 * @param {BN} num
 * @return {number}
 */
BN.prototype.ucmp = function (num) {
  if (this.length !== num.length) {
    return this.length > num.length ? 1 : -1
  }

  for (var i = this.length - 1; i >= 0; --i) {
    if (this.words[i] !== num.words[i]) {
      return this.words[i] > num.words[i] ? 1 : -1
    }
  }

  return 0
}

/**
 * @param {BN} output
 * @return {BN}
 */
BN.prototype._isplit = function (output) {
  output.length = Math.min(this.length, 9)
  for (var i = 0; i < output.length; ++i) {
    output.words[i] = this.words[i]
  }

  if (this.length <= 9) {
    this.words[0] = 0
    this.length = 1
    return this
  }

  // Shift by 9 limbs
  var prev = this.words[9]
  output.words[output.length++] = prev & 0x003fffff

  for (i = 10; i < this.length; ++i) {
    var next = this.words[i]
    this.words[i - 10] = ((next & 0x003fffff) << 4) | (prev >>> 22)
    prev = next
  }
  this.words[i - 10] = prev >>> 22
  this.length -= 9

  return this
}

/**
 * @return {BN}
 */
BN.prototype._imulK = function () {
  this.words[this.length] = 0
  this.words[this.length + 1] = 0
  this.length += 2

  for (var i = 0, lo = 0; i < this.length; ++i) {
    var w = this.words[i]
    lo += w * 0x3d1
    this.words[i] = lo & 0x03ffffff
    lo = w * 0x40 + ((lo / 0x04000000) | 0)
  }

  if (this.words[this.length - 1] === 0) {
    this.length -= 1
    if (this.words[this.length - 1] === 0) {
      this.length -= 1
    }
  }

  return this
}

/**
 * @return {BN}
 */
BN.prototype._redIReduce = function () {
  this._isplit(BN.tmp)._imulK().iadd(BN.tmp)
  if (this.length > 10 || (this.length === 10 && this.words[9] > 0x003fffff)) {
    this._isplit(BN.tmp)._imulK().iadd(BN.tmp)
  }

  var cmp = this.ucmp(BN.p)
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

/**
 * @return {BN}
 */
BN.prototype.redIsOverflow = function () {
  return this.ucmp(BN.p) >= 0
}

/**
 * @return {BN}
 */
BN.prototype.redNeg = function () {
  if (this.isZero()) {
    return BN.fromNumber(0)
  }

  return BN.p.sub(this)
}

/**
 * @param {BN} num
 * @return {BN}
 */
BN.prototype.redAdd = function (num) {
  var res = this.add(num)
  if (res.ucmp(BN.p) >= 0) {
    res.isub(BN.p)
  }

  return res
}

/**
 * @param {BN} num
 * @return {BN}
 */
BN.prototype.redIAdd = function (num) {
  this.iadd(num)
  if (this.ucmp(BN.p) >= 0) {
    this.isub(BN.p)
  }

  return this
}

/**
 * @return {BN}
 */
BN.prototype.redIAdd7 = function () {
  this._iuaddn(7)
  if (this.ucmp(BN.p) >= 0) {
    this.isub(BN.p)
  }

  return this
}

/**
 * @param {BN} num
 * @return {BN}
 */
BN.prototype.redSub = function (num) {
  var res = this.sub(num)
  if (res.negative !== 0) {
    res.iadd(BN.p)
  }

  return res
}

/**
 * @param {BN} num
 * @return {BN}
 */
BN.prototype.redISub = function (num) {
  this.isub(num)
  if (this.negative !== 0) {
    this.iadd(BN.p)
  }

  return this
}

/**
 * @param {BN} num
 * @return {BN}
 */
BN.prototype.redMul = function (num) {
  return this.umul(num)._redIReduce()
}

/**
 * @return {BN}
 */
BN.prototype.redSqr = function () {
  return this.umul(this)._redIReduce()
}

/**
 * @return {BN}
 */
BN.prototype.redSqrt = function () {
  if (this.isZero()) {
    return this.clone()
  }

  // res = this ** ((p+1)/4)

  var windowSize = 4
  var wnd = new Array(1 << windowSize)
  wnd[0] = BN.fromNumber(1)
  wnd[1] = this
  for (var k = 2; k < wnd.length; ++k) {
    wnd[k] = this.redMul(wnd[k - 1])
  }

  var res = wnd[0]
  var current = 0
  var currentLen = 0

  // TODO: make flatten
  for (var i = 9, start = 20; i >= 0; --i, start = 26) {
    var word = BN._sqrtPower.words[i]
    for (var j = start - 1; j >= 0; j--) {
      var bit = (word >> j) & 1
      if (res !== wnd[0]) {
        res = res.redSqr()
      }

      if (bit === 0 && current === 0) {
        currentLen = 0
        continue
      }

      current <<= 1
      current |= bit
      currentLen += 1
      if (currentLen !== windowSize && (i !== 0 || j !== 0)) {
        continue
      }

      res = res.redMul(wnd[current])
      currentLen = 0
      current = 0
    }
  }

  return res
}

/**
 * @return {BN}
 */
BN.prototype.redInvm = function () {
  var a = this.clone()
  var b = BN.p.clone()

  var x1 = BN.fromNumber(1)
  var x2 = BN.fromNumber(0)

  while (a.gtOne() && b.gtOne()) {
    for (var i = 0, im = 1; (a.words[0] & im) === 0 && i < 26; ++i, im <<= 1);
    if (i > 0) {
      a.iushrn(i)
      while (i-- > 0) {
        if (x1.isOdd()) {
          x1.iadd(BN.p)
        }

        x1.iushrn(1)
      }
    }

    for (var j = 0, jm = 1; (b.words[0] & jm) === 0 && j < 26; ++j, jm <<= 1);
    if (j > 0) {
      b.iushrn(j)
      while (j-- > 0) {
        if (x2.isOdd()) {
          x2.iadd(BN.p)
        }

        x2.iushrn(1)
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

  var res
  if (a.length === 1 && a.words[0] === 1) {
    res = x1
  } else {
    res = x2
  }

  if (res.negative !== 0) {
    res.iadd(BN.p)
  }

  if (res.negative !== 0) {
    res.negative = 0
    return res._redIReduce().redNeg()
  } else {
    return res._redIReduce()
  }
}

/**
 * Represent big number in a w-NAF form
 * @param {number} w
 * @return {number[]}
 */
BN.prototype.getNAF = function (w) {
  var naf = []
  var ws = 1 << w
  var ws2m1 = (ws << 1) - 1

  var k = this.clone()
  while (!k.isZero()) {
    var i = 0
    for (var d = 1; (k.words[0] & d) === 0 && i < 26; ++i, d <<= 1) {
      naf.push(0)
    }

    if (i !== 0) {
      k.iushrn(i)
    } else {
      var mod = k.words[0] & ws2m1
      if (mod >= ws) {
        naf.push(ws - mod)
        k._iuaddn(mod - ws).iushrn(1)
      } else {
        k.words[0] -= mod
        naf.push(mod)
        if (!k.isZero()) {
          for (i = w - 1; i > 0; --i) {
            naf.push(0)
          }

          k.iushrn(w)
        }
      }
    }
  }

  return naf
}

BN.n = BN.fromBuffer(new Buffer('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 'hex'))
BN.nh = BN.n.clone().iushrn(1)
BN.p = BN.fromBuffer(new Buffer('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 'hex'))
BN.psn = BN.p.sub(BN.n)
BN._reduceDevisor = BN.n.clone().iushl4()
BN._sqrtPower = BN.p.add(BN.fromNumber(1)).iushrn(2)
BN.tmp = new BN()
BN.tmp.words = new Array(20)

// WTF?! it speed-up benchmark on ~20%
;(function () {
  var x = BN.fromNumber(1)
  x.words[3] = 0
})()

module.exports = BN
