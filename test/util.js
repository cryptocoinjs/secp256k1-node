'use strict'
/* global it */

var crypto = require('crypto')
var BN = require('bn.js')
var EC = require('elliptic').ec
var ProgressBar = require('progress')
var XorShift128Plus = require('xorshift.js').XorShift128Plus

var ec = exports.ec = new EC('secp256k1')
exports.BN_ZERO = new BN(0)
exports.BN_ONE = new BN(1)

var prngs = exports.prngs = {
  privateKey: null,
  tweak: null,
  message: null
}

exports.setSeed = function (seed) {
  if (Buffer.isBuffer(seed)) seed = seed.toString('hex')
  console.log('Set seed: ' + seed)

  var prng = new XorShift128Plus(seed)
  for (var i = 0; i < 100; ++i) prng.random()

  prngs.privateKey = new XorShift128Plus(prng.randomBytes(16).toString('hex'))
  prngs.tweak = new XorShift128Plus(prng.randomBytes(16).toString('hex'))
  prngs.message = new XorShift128Plus(prng.randomBytes(16).toString('hex'))
}

exports.getPrivateKey = function () {
  while (true) {
    var privateKey = prngs.privateKey.randomBytes(32)
    var bn = new BN(privateKey)
    if (bn.cmp(exports.BN_ZERO) === 1 && bn.cmp(ec.curve.n) === -1) {
      return privateKey
    }
  }
}

exports.getPublicKey = function (privateKey) {
  var publicKey = ec.keyFromPrivate(privateKey).getPublic()
  return {
    compressed: new Buffer(publicKey.encode(null, true)),
    uncompressed: new Buffer(publicKey.encode(null, false))
  }
}

exports.getSignature = function (message, privateKey) {
  var sig = exports.sign(message, privateKey)
  return sig.signatureLowS
}

exports.getTweak = function () {
  while (true) {
    var tweak = prngs.tweak.randomBytes(32)
    var bn = new BN(tweak)
    if (bn.cmp(ec.curve.n) === -1) {
      return tweak
    }
  }
}

exports.getMessage = function () {
  return prngs.message.randomBytes(32)
}

exports.sign = function (message, privateKey) {
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

exports.ecdh = function (publicKey, privateKey) {
  var secret = ec.keyFromPrivate(privateKey)
  var point = ec.keyFromPublic(publicKey)
  var sharedSecret = new BN(secret.derive(point).encode(null, 32))
  return crypto.createHash('sha256').update(sharedSecret).digest()
}

function repeatIt (it, args) {
  it(args[0], function () {
    var bar = new ProgressBar(':percent (:current/:total), :elapseds elapsed, eta :etas', {
      total: args[1],
      stream: exports.progressStream
    })

    while (bar.curr !== args[1]) {
      args[2]()
      bar.tick()
    }
  })
}

exports.repeatIt = function () { repeatIt(it, arguments) }
exports.repeatIt.skip = function () { repeatIt(it.skip, arguments) }
exports.repeatIt.only = function () { repeatIt(it.only, arguments) }

exports.env = {
  repeat: parseInt(global.__env__ && global.__env__.RANDOM_TESTS_REPEAT ||
                   process.env.RANDOM_TESTS_REPEAT ||
                   100,
                   10),
  isTravis: global.__env__ && global.__env__.TRAVIS ||
            process.env.TRAVIS ||
            false,
  seed: global.__env__ && global.__env__.SEED ||
        process.env.SEED ||
        crypto.randomBytes(32)
}

// stream for progress package
exports.progressStream = process.stdout
if (process.browser) {
  exports.progressStream = {
    isTTY: true,
    columns: 100,
    clearLine: function () {},
    cursorTo: function () {},
    write: console.log.bind(console)
  }
}

// turn off on travis
if (exports.env.isTravis) {
  exports.progressStream = function () {}
}
