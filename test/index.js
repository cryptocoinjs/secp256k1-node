//tests against the `ecdsa` module
var ecdsa = require('ecdsa')
var BigInteger = require('bigi')
var assert = require('assert')
var sr = require('secure-random')
var CoinKey = require('coinkey')
var ecdsaNative = require('../')

var privateKey = sr.randomBuffer(32)
var msg = sr.randomBuffer(32)
var ck

var pubKey
var compactSig

describe('it should handle basic ecdsa ops', function () {

  it('should create a public key', function () {
    ck = new CoinKey(privateKey, true)
    pubKey = ecdsaNative.createPublicKey(privateKey, true)
    assert(pubKey.toString('hex') === ck.publicKey.toString('hex'), 'incorrect public key')
  })

  it('should sign a message with a DER sig', function () {
    var sig = ecdsaNative.sign(msg, privateKey, true)
    var s = ecdsa.parseSig(sig)
    assert(ecdsa.verify(msg, s, ck.publicKey), 'the message should verify')
  })

  it('should sign a message async', function (done) {
    ecdsaNative.sign(msg, privateKey, true, function (err, sig) {
      var s = ecdsa.parseSig(sig)
      assert(ecdsa.verify(msg, s, ck.publicKey), 'the message should verify')
      done()
    })
  })

  it('should verify a signature', function () {
    //testing verification
    var sig2 = ecdsa.sign(msg, ck.privateKey)
    sig2 = new Buffer(ecdsa.serializeSig(sig2))
    assert(ecdsaNative.verify(msg, sig2, pubKey), 'should verify signature')
  })

  it('should NOT verify an invalid signature', function () {
    //testing verification
    var sig2 = ecdsa.sign(msg, ck.privateKey)
    sig2 = new Buffer(ecdsa.serializeSig(sig2))
    sig2[0] = 0xff
    assert(!ecdsaNative.verify(msg, sig2, pubKey), 'should NOT verify invalid signature')
  })

  it('should verify a signature async', function (done) {
    //testing verification
    var sig2 = ecdsa.sign(msg, ck.privateKey)
    sig2 = new Buffer(ecdsa.serializeSig(sig2))
    var r = ecdsaNative.verify(msg, sig2, pubKey)
    console.log(r)
    ecdsaNative.verify(msg, sig2, pubKey, function (result) {
      console.log(result)
      assert(result, 'the result should equal one')
      done()
    })
  })

  it('should create a compact signature', function () {
    var sig = ecdsaNative.sign(msg, privateKey)
      //save to use to test verifyCompact
    compactSig = sig

    var s = {
        r: BigInteger.fromBuffer(sig.signature.slice(0, 32)),
        s: BigInteger.fromBuffer(sig.signature.slice(32, 64)),
        v: sig.recovery
      },
      e = BigInteger.fromBuffer(msg),
      key = ecdsa.recoverPubKey(e, s, s.v)

    assert(key.getEncoded().toString('hex') === pubKey.toString('hex'), 'the recovered Key should be the same as the public key')
  })

  it('should create a compact signature async', function(done) {
    ecdsaNative.sign(msg, privateKey, function(result, sig, recoveryId) {
      var s = {
          r: BigInteger.fromBuffer(sig.slice(0, 32)),
          s: BigInteger.fromBuffer(sig.slice(32, 64)),
          v: recoveryId
        },
        e = BigInteger.fromBuffer(msg),
        key = ecdsa.recoverPubKey(e, s, s.v)

      assert(key.getEncoded().toString('hex') === pubKey.toString('hex'), 'the recovered Key should be the same as the public key')
      done()
    })
  })

  it('should recover a compact signature and return the public key', function() {
    var sig = ecdsaNative.recover(msg, compactSig)
    assert(sig.toString('hex') === pubKey.toString('hex'))
  })

  it('should recover a compact signature and return the public key, async', function(done) {
    ecdsaNative.recover(msg, compactSig, function(result, sig) {
      assert(sig.toString('hex') === pubKey.toString('hex'))
      done()
    })
  })
})


describe('invalid inputs', function() {
  it('should not crash when recoverId is out of bounds - sync', function() {
    assert.throws(function(){
      var sig = ecdsaNative.recover(msg, compactSig.signature, -27, true)
    })
  })

  it('should not crash when recoverId is out of bounds - async', function() {
    assert.throws(function(){
      ecdsaNative.recover(msg, compactSig.signature, -27, true, function(err, sig) {
        assert(err)
        assert.strictEqual(sig, undefined)
      })
    })
  })

  it('should not crash when giving it an undefined private key', function(done) {
    try{
      ecdsaNative.sign(undefined, new Buffer('test'))
    }catch(e){
      done()
    }
  })


  it('should not crash when given an undefined privateKey in createPublicKey', function(done){
    try{
      ecdsaNative.createPublicKey()
    }catch(e){
      done()
    }
  })
})
