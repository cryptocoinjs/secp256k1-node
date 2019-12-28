'use strict'

var BN = require('bn.js')

// result = value ** ((p+1)/4)
var PWR = new BN('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 'hex').addn(1).iushrn(2)
console.log(PWR.toString(16))
var windowSize = 4

var operations = []
var reqValues = {}
var current = 0
var currentLen = 0
for (var i = PWR.length - 1, start = PWR.bitLength() % 26; i >= 0; --i, start = 26) {
  var word = PWR.words[i]
  for (var j = start - 1; j >= 0; j--) {
    var bit = (word >> j) & 1
    if (operations.length > 0 && operations[operations.length - 1].op === 'sqr') {
      operations[operations.length - 1].v += 1
    } else {
      operations.push({ op: 'sqr', v: 1 })
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

    operations.push({ op: 'mul', v: current })
    reqValues[current] = true
    currentLen = 0
    current = 0
  }
}

console.log(Object.keys(reqValues), operations)
console.log('==================================================')

var src = [
  'var wv2 = this.redSqr()', // this ** 2
  'var wv4 = wv2.redSqr()', // this ** 4
  'var wv12 = wv4.redSqr().redMul(wv4)', // this ** 12
  'var wv14 = wv12.redMul(wv2)', // this ** 14
  'var wv15 = wv14.redMul(this)', // this ** 15
  '',
  'var out = wv15',
  'for (var i = 0; i < 54; ++i) {',
  '  out = out.redSqr().redSqr().redSqr().redSqr().redMul(wv15)',
  '}',
  'out = out.redSqr().redSqr().redSqr().redSqr().redMul(wv14)',
  'for (i = 0; i < 5; ++i) {',
  '  out = out.redSqr().redSqr().redSqr().redSqr().redMul(wv15)',
  '}',
  'out = out.redSqr().redSqr().redSqr().redSqr().redMul(wv12)',
  'out = out.redSqr().redSqr().redSqr().redSqr().redSqr().redSqr().redMul(wv12)',
  '',
  'return out'
]

console.log(src.join('\n'))
