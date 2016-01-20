#!/usr/bin/env node
'use strict'

var assert = require('assert')
var BN = require('bn.js')

var ecparams = require('../lib/ecparams')
ecparams.initG()

/**
 * @param {BN} num
 * @return {[BN, BN]}
 */
function getEndoRoots (num) {
  // Find roots of for x^2 + x + 1 in F
  // Root = (-1 +- Sqrt(-3)) / 2

  var red = num === ecparams.p ? ecparams.red : BN.mont(num)
  var tinv = new BN(2).toRed(red).redInvm()
  var ntinv = tinv.redNeg()

  var s = new BN(3).toRed(red).redNeg().redSqrt().redMul(tinv)

  var l1 = ntinv.redAdd(s).fromRed()
  var l2 = ntinv.redSub(s).fromRed()
  return [l1, l2]
}

/**
 * @param {BN} lambda
 * @return {{a: BN, b: BN}, {a: BN, b: BN}}
 */
function getEndoBasis (lambda) {
  // aprxSqrt >= sqrt(this.n)
  var aprxSqrt = ecparams.n.ushrn(Math.floor(ecparams.n.bitLength() / 2))

  // 3.74
  // Run EGCD, until r(L + 1) < aprxSqrt
  var u = lambda
  var v = ecparams.n.clone()
  var x1 = new BN(1)
  var y1 = new BN(0)
  var x2 = new BN(0)
  var y2 = new BN(1)

  // NOTE: all vectors are roots of: a + b * lambda = 0 (mod n)
  var a0
  var b0
  // First vector
  var a1
  var b1
  // Second vector
  var a2
  var b2

  var prevR
  var i = 0
  var r
  var x
  while (u.cmpn(0) !== 0) {
    var q = v.div(u)
    r = v.sub(q.mul(u))
    x = x2.sub(q.mul(x1))
    var y = y2.sub(q.mul(y1))

    if (!a1 && r.cmp(aprxSqrt) < 0) {
      a0 = prevR.neg()
      b0 = x1
      a1 = r.neg()
      b1 = x
    } else if (a1 && ++i === 2) {
      break
    }
    prevR = r

    v = u
    u = r
    x2 = x1
    x1 = x
    y2 = y1
    y1 = y
  }
  a2 = r.neg()
  b2 = x

  var len1 = a1.sqr().add(b1.sqr())
  var len2 = a2.sqr().add(b2.sqr())
  if (len2.cmp(len1) >= 0) {
    a2 = a0
    b2 = b0
  }

  // Normalize signs
  if (a1.negative) {
    a1 = a1.neg()
    b1 = b1.neg()
  }
  if (a2.negative) {
    a2 = a2.neg()
    b2 = b2.neg()
  }

  return [{a: a1, b: b1}, {a: a2, b: b2}]
}

// Compute beta and lambda, that lambda * P = (beta * Px; Py)
var betas = getEndoRoots(ecparams.p)
// Choose the smallest beta
var beta = (betas[0].cmp(betas[1]) < 0 ? betas[0] : betas[1]).toRed(ecparams.red)

// Choose the lambda that is matching selected beta
var lambda
var lambdas = getEndoRoots(ecparams.n)
if (ecparams.g.mul(lambdas[0]).x.cmp(ecparams.g.x.redMul(beta)) === 0) {
  lambda = lambdas[0]
} else {
  lambda = lambdas[1]
  assert(ecparams.g.mul(lambda).x.cmp(ecparams.g.x.redMul(beta)) === 0)
}

// Get basis vectors, used for balanced length-two representation
var basis = getEndoBasis(lambda)

console.log(JSON.stringify({
  beta: beta.toString('hex', 32),
  lambda: lambda.toString('hex', 32),
  basis: [{
    a: basis[0].a.toString('hex'),
    b: basis[0].b.toString('hex')
  }, {
    a: basis[1].a.toString('hex'),
    b: basis[1].b.toString('hex')
  }]
}, null, 2).replace(/"/g, '\''))
