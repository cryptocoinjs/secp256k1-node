'use strict'
var messages = require('../lib/messages')

var util = require('./util')

module.exports = function (t, secp256k1) {
  t.test('signatureNormalize', function (t) {
    t.test('signature should be a Buffer', function (t) {
      t.throws(function () {
        secp256k1.signatureNormalize(null)
      }, new RegExp('^TypeError: ' + messages.ECDSA_SIGNATURE_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('invalid length', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(message, privateKey).slice(1)
        secp256k1.signatureNormalize(signature)
      }, new RegExp('^RangeError: ' + messages.ECDSA_SIGNATURE_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('parse fail (r equal N)', function (t) {
      t.throws(function () {
        var signature = Buffer.concat([
          new Buffer(util.ec.curve.n.toArray(null, 32)),
          util.BN_ONE.toArrayLike(Buffer, null, 32)
        ])
        secp256k1.signatureNormalize(signature)
      }, new RegExp('^Error: ' + messages.ECDSA_SIGNATURE_PARSE_FAIL + '$'))
      t.end()
    })

    t.test('normalize return same signature (s equal n/2)', function (t) {
      var signature = Buffer.concat([
        util.BN_ONE.toArrayLike(Buffer, null, 32),
        new Buffer(util.ec.nh.toArray(null, 32))
      ])
      var result = secp256k1.signatureNormalize(signature)
      t.same(result, signature)
      t.end()
    })

    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var message = util.getMessage()
      var privateKey = util.getPrivateKey()

      var sigObj = util.sign(message, privateKey)
      var result = secp256k1.signatureNormalize(sigObj.signature)
      t.same(result, sigObj.signatureLowS)
      t.end()
    })

    t.end()
  })

  t.test('signatureExport', function (t) {
    t.test('signature should be a Buffer', function (t) {
      t.throws(function () {
        secp256k1.signatureExport(null)
      }, new RegExp('^TypeError: ' + messages.ECDSA_SIGNATURE_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('invalid length', function (t) {
      t.throws(function () {
        var privateKey = util.getPrivateKey()
        var message = util.getMessage()
        var signature = util.getSignature(message, privateKey).slice(1)
        secp256k1.signatureExport(signature)
      }, new RegExp('^RangeError: ' + messages.ECDSA_SIGNATURE_LENGTH_INVALID + '$'))
      t.end()
    })

    t.test('parse fail (r equal N)', function (t) {
      t.throws(function () {
        var signature = Buffer.concat([
          new Buffer(util.ec.n.toArray(null, 32)),
          util.BN_ONE.toArrayLike(Buffer, null, 32)
        ])
        secp256k1.signatureExport(signature)
      }, new RegExp('^Error: ' + messages.ECDSA_SIGNATURE_PARSE_FAIL + '$'))
      t.end()
    })

    t.end()
  })

  t.test('signatureImport', function (t) {
    t.test('signature should be a Buffer', function (t) {
      t.throws(function () {
        secp256k1.signatureImport(null)
      }, new RegExp('^TypeError: ' + messages.ECDSA_SIGNATURE_TYPE_INVALID + '$'))
      t.end()
    })

    t.test('parse fail', function (t) {
      t.throws(function () {
        secp256k1.signatureImport(new Buffer(1))
      }, new RegExp('^Error: ' + messages.ECDSA_SIGNATURE_PARSE_DER_FAIL + '$'))
      t.end()
    })

    t.end()
  })

  t.test('signatureExport/signatureImport', function (t) {
    util.repeat(t, 'random tests', util.env.repeat, function (t) {
      var message = util.getMessage()
      var privateKey = util.getPrivateKey()

      var signature = util.sign(message, privateKey).signatureLowS

      var der = secp256k1.signatureExport(signature)
      var result = secp256k1.signatureImport(der)
      t.same(result, signature)
      t.end()
    })

    t.end()
  })
}
