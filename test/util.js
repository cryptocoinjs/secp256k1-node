'use strict'

var crypto = require('crypto')
var BN = require('bn.js')
var EC = require('elliptic').ec
var ProgressBar = require('progress')

var PRNG = require('./prng')

var ec = exports.ec = new EC('secp256k1')
exports.BN_ZERO = new BN(0)
exports.BN_ONE = new BN(1)

var prngs = exports.prngs = {
  privateKey: new PRNG(),
  tweak: new PRNG(),
  message: new PRNG()
}

/**
 * @param {(Buffer|string)} [seed]
 */
exports.setSeed = function (seed) {
  console.log('Set seed: ' + (Buffer.isBuffer(seed) ? seed.toString('hex') : seed))

  var prng = new PRNG(seed)
  prngs.privateKey.setSeed(prng.random())
  prngs.tweak.setSeed(prng.random())
  prngs.message.setSeed(prng.random())
}

/**
 * @return {Buffer}
 */
exports.getPrivateKey = function () {
  while (true) {
    var privateKey = prngs.privateKey.random()
    var bn = new BN(privateKey)
    if (bn.cmp(exports.BN_ZERO) === 1 && bn.cmp(ec.curve.n) === -1) {
      return privateKey
    }
  }
}

/**
 * @param {Buffer} privateKey
 * @return {{compressed: Buffer, uncompressed: Buffer}}
 */
exports.getPublicKey = function (privateKey) {
  var publicKey = ec.keyFromPrivate(privateKey).getPublic()
  return {
    compressed: new Buffer(publicKey.encode(null, true)),
    uncompressed: new Buffer(publicKey.encode(null, false))
  }
}

/**
 * @param {Buffer} message
 * @param {Buffer} privateKey
 * @return {Buffer}
 */
exports.getSignature = function (message, privateKey) {
  var sig = exports.sign(message, privateKey)
  return sig.signatureLowS
}

/**
 * @return {Buffer}
 */
exports.getTweak = function () {
  while (true) {
    var tweak = prngs.tweak.random()
    var bn = new BN(tweak)
    if (bn.cmp(ec.curve.n) === -1) {
      return tweak
    }
  }
}

/**
 * @return {Buffer}
 */
exports.getMessage = function () {
  return prngs.message.random()
}

/**
 * @param {Buffer} message
 * @param {Buffer} privateKey
 * @return {{signature: string, recovery: number}}
 */
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

/**
 * @param {Buffer} publicKey
 * @param {Buffer} privateKey
 * @return {Buffer}
 */
exports.ecdh = function (publicKey, privateKey) {
  var secret = ec.keyFromPrivate(privateKey)
  var point = ec.keyFromPublic(publicKey)
  var sharedSecret = new BN(secret.derive(point).encode(null, 32))
  return crypto.createHash('sha256').update(sharedSecret).digest()
}

/**
 * @param {function} it
 * @param {*[]} args
 */
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

/*
 * @param {string} description
 * @param {number} total
 * @param {function} fn
 */
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
