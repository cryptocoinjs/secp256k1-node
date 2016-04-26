'use strict'
var crypto = require('crypto')
var BN = require('bn.js')
var EC = require('elliptic').ec
var XorShift128Plus = require('xorshift.js').XorShift128Plus

var ec = new EC('secp256k1')
var BN_ZERO = new BN(0)
var BN_ONE = new BN(1)

var prngs = { privateKey: null, tweak: null, message: null }

function setSeed (seed) {
  if (Buffer.isBuffer(seed)) seed = seed.toString('hex')
  console.log('Set seed: ' + seed)

  var prng = new XorShift128Plus(seed)
  for (var i = 0; i < 100; ++i) prng.random()

  prngs.privateKey = new XorShift128Plus(prng.randomBytes(16).toString('hex'))
  prngs.tweak = new XorShift128Plus(prng.randomBytes(16).toString('hex'))
  prngs.message = new XorShift128Plus(prng.randomBytes(16).toString('hex'))
}

function getPrivateKey () {
  while (true) {
    var privateKey = prngs.privateKey.randomBytes(32)
    var bn = new BN(privateKey)
    if (bn.cmp(BN_ZERO) === 1 && bn.cmp(ec.curve.n) === -1) return privateKey
  }
}

function getPublicKey (privateKey) {
  var publicKey = ec.keyFromPrivate(privateKey).getPublic()
  return {
    compressed: new Buffer(publicKey.encode(null, true)),
    uncompressed: new Buffer(publicKey.encode(null, false))
  }
}

function getSignature (message, privateKey) {
  return sign(message, privateKey).signatureLowS
}

function getTweak () {
  while (true) {
    var tweak = prngs.tweak.randomBytes(32)
    var bn = new BN(tweak)
    if (bn.cmp(ec.curve.n) === -1) return tweak
  }
}

function getMessage () {
  return prngs.message.randomBytes(32)
}

function sign (message, privateKey) {
  var ecSig = ec.sign(message, privateKey, {canonical: false})

  var signature = new Buffer(ecSig.r.toArray('null', 32).concat(ecSig.s.toArray('null', 32)))
  var recovery = ecSig.recoveryParam
  if (ecSig.s.cmp(ec.nh) === 1) {
    ecSig.s = ec.n.sub(ecSig.s)
    recovery ^= 1
  }
  var signatureLowS = new Buffer(ecSig.r.toArray('null', 32).concat(ecSig.s.toArray('null', 32)))

  return {
    signature: signature,
    signatureLowS: signatureLowS,
    recovery: recovery
  }
}

function ecdh (publicKey, privateKey) {
  var secret = ec.keyFromPrivate(privateKey)
  var point = ec.keyFromPublic(publicKey)
  var sharedSecret = new BN(secret.derive(point).encode(null, 32))
  return crypto.createHash('sha256').update(sharedSecret).digest()
}

var env = {
  repeat: parseInt(global.__env__ && global.__env__.RANDOM_TESTS_REPEAT ||
                   process.env.RANDOM_TESTS_REPEAT ||
                   100,
                   10),
  seed: global.__env__ && global.__env__.SEED ||
        process.env.SEED ||
        crypto.randomBytes(32)
}

function _repeat (test, name, total, fn) {
  test(name, function (t) {
    var curr = 0
    var _end = t.end

    t.end = function () {
      curr += 1
      setTimeout(next, 0)
    }

    function next () {
      if (curr >= total) return _end.call(t)
      fn(t)
    }

    next()
  })
}

function repeat (t, name, total, fn) { _repeat(t.test, name, total, fn) }
repeat.skip = function (t, name, total, fn) { _repeat(t.skip, name, total, fn) }
repeat.only = function (t, name, total, fn) { _repeat(t.only, name, total, fn) }

module.exports = {
  ec: ec,
  BN_ZERO: BN_ZERO,
  BN_ONE: BN_ONE,

  prngs: prngs,
  setSeed: setSeed,
  getPrivateKey: getPrivateKey,
  getPublicKey: getPublicKey,
  getSignature: getSignature,
  getTweak: getTweak,
  getMessage: getMessage,

  sign: sign,
  ecdh: ecdh,

  env: env,
  repeat: repeat
}
