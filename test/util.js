var randomBytes = require('crypto').randomBytes
var createHash = require('create-hash')
var BigInteger = require('bigi')
var ecdsa = require('ecdsa')
var ECKey = require('eckey')
var ecurve = require('ecurve')
var ProgressBar = require('progress')

var SECP256K1_N = require('./const').SECP256K1_N
var Promise = require('../lib/promise')

var ecparams = ecurve.getCurveByName('secp256k1')

/**
 * @return {Buffer}
 */
exports.getPrivateKey = function () {
  while (true) {
    var privKey = randomBytes(32)
    var bn = BigInteger.fromBuffer(privKey)
    if (bn.compareTo(BigInteger.ZERO) !== 0 && bn.compareTo(SECP256K1_N) < 0) {
      return privKey
    }
  }
}

/**
 * @return {Buffer}
 */
exports.getPublicKey = function () {
  var eckey = new ECKey(exports.getPrivateKey())
  return eckey.publicKey
}

/**
 * @return {Buffer}
 */
exports.getSignature = function () {
  var sig = exports.signSync(exports.getMessage(), exports.getPrivateKey())
  return sig.signature
}

/**
 * @return {Buffer}
 */
exports.getTweak = function () {
  while (true) {
    var tweak = randomBytes(32)
    var bn = BigInteger.fromBuffer(tweak)
    if (bn.compareTo(SECP256K1_N) < 0) {
      return tweak
    }
  }
}

/**
 * @return {Buffer}
 */
exports.getMessage = function () {
  return randomBytes(32)
}

/**
 * @param {Buffer} msg
 * @param {Buffer} privKey
 * @return {{signature: string, recovery: number}}
 */
exports.signSync = function (msg, privKey) {
  var obj = ecdsa.sign(msg, privKey)
  return {
    signature: Buffer.concat([obj.r.toBuffer(32), obj.s.toBuffer(32)]),
    recovery: null // TODO
  }
}

/**
 * @param {Buffer} pubKey
 * @param {Buffer} privKey
 * @return {Buffer}
 */
exports.ecdhSync = function (pubKey, privKey) {
  var point = ecurve.Point.decodeFrom(ecparams, pubKey)
  var buf = point.multiply(BigInteger.fromBuffer(privKey)).getEncoded(true)
  return createHash('sha256').update(buf).digest()
}

var stream = process.stdout
if (process.browser) {
  stream = {
    isTTY: true,
    columns: 100,
    clearLine: function () {},
    cursorTo: function () {},
    write: console.log.bind(console)
  }
}

/**
 * @param {function} it
 * @param {*[]} args
 */
function repeatIt (it, args) {
  it(args[0], function () {
    var bar = new ProgressBar(':percent (:current/:total), :elapseds elapsed, eta :etas', {
      total: args[1],
      stream: stream
    })

    return new Promise(function (resolve, reject) {
      function next () {
        if (bar.curr === args[1]) {
          return resolve()
        }

        Promise.resolve()
          .then(function () {
            return args[2]()
          })
          .then(function () {
            bar.tick()
          })
          .then(next, reject)
      }

      next()
    })
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
