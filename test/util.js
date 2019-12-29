const crypto = require('crypto')
const BN = require('bn.js')
const EC = require('elliptic').ec
const XorShift128Plus = require('xorshift.js').XorShift128Plus

const ec = new EC('secp256k1')
const BN_ZERO = new BN(0)
const BN_ONE = new BN(1)

const prngs = { privateKey: null, tweak: null, message: null }

function setSeed (seed) {
  if (Buffer.isBuffer(seed)) seed = seed.toString('hex')
  console.log('Set seed: ' + seed)

  const prng = new XorShift128Plus(seed)
  for (let i = 0; i < 100; ++i) prng.random()

  prngs.privateKey = new XorShift128Plus(prng.randomBytes(16).toString('hex'))
  prngs.tweak = new XorShift128Plus(prng.randomBytes(16).toString('hex'))
  prngs.message = new XorShift128Plus(prng.randomBytes(16).toString('hex'))
}

function getPrivateKey () {
  while (true) {
    const privateKey = prngs.privateKey.randomBytes(32)
    const bn = new BN(privateKey)
    if (bn.cmp(BN_ZERO) === 1 && bn.cmp(ec.curve.n) === -1) return privateKey
  }
}

function getPublicKey (privateKey) {
  const publicKey = ec.keyFromPrivate(privateKey).getPublic()
  return {
    compressed: Buffer.from(publicKey.encode(null, true)),
    uncompressed: Buffer.from(publicKey.encode(null, false))
  }
}

function getSignature (message, privateKey) {
  return sign(message, privateKey).signatureLowS
}

function getTweak () {
  while (true) {
    const tweak = prngs.tweak.randomBytes(32)
    const bn = new BN(tweak)
    if (bn.cmp(ec.curve.n) === -1) return tweak
  }
}

function getMessage () {
  return prngs.message.randomBytes(32)
}

function sign (message, privateKey) {
  const ecSig = ec.sign(message, privateKey, { canonical: false })

  const signature = Buffer.concat([
    ecSig.r.toArrayLike(Buffer, 'be', 32),
    ecSig.s.toArrayLike(Buffer, 'be', 32)
  ])
  let recovery = ecSig.recoveryParam
  if (ecSig.s.cmp(ec.nh) === 1) {
    ecSig.s = ec.n.sub(ecSig.s)
    recovery ^= 1
  }
  const signatureLowS = Buffer.concat([
    ecSig.r.toArrayLike(Buffer, 'be', 32),
    ecSig.s.toArrayLike(Buffer, 'be', 32)
  ])

  return {
    signature: signature,
    signatureLowS: signatureLowS,
    recovery: recovery
  }
}

const env = {
  repeat: parseInt((global.__env__ && global.__env__.RANDOM_TESTS_REPEAT) || process.env.RANDOM_TESTS_REPEAT || 1, 10),
  seed: (global.__env__ && global.__env__.SEED) || process.env.SEED || crypto.randomBytes(32)
}

function _repeat (test, name, total, fn) {
  test(name, (t) => {
    for (let i = 0; i < total; ++i) fn(t)
    t.end()
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

  env: env,
  repeat: repeat
}
