import { randomBytes, createHash } from 'crypto'
import BN from 'bn.js'
import { ec as EC } from 'elliptic'
import { XorShift128Plus } from 'xorshift.js'

import * as _messages from '../es/messages'
export const messages = _messages

export const ec = new EC('secp256k1')
export const BN_ZERO = new BN(0)
export const BN_ONE = new BN(1)

export const prngs = { privateKey: null, tweak: null, message: null }

export function setSeed (seed) {
  if (Buffer.isBuffer(seed)) seed = seed.toString('hex')
  console.log(`Set seed: ${seed}`)

  const prng = new XorShift128Plus(seed)
  for (let i = 0; i < 100; ++i) prng.random()

  prngs.privateKey = new XorShift128Plus(prng.randomBytes(16).toString('hex'))
  prngs.tweak = new XorShift128Plus(prng.randomBytes(16).toString('hex'))
  prngs.message = new XorShift128Plus(prng.randomBytes(16).toString('hex'))
}

export function getPrivateKey () {
  while (true) {
    const privateKey = prngs.privateKey.randomBytes(32)
    const bn = new BN(privateKey)
    if (bn.cmp(BN_ZERO) === 1 && bn.cmp(ec.curve.n) === -1) return privateKey
  }
}

export function getPublicKey (privateKey) {
  const publicKey = ec.keyFromPrivate(privateKey).getPublic()
  return {
    compressed: Buffer.from(publicKey.encode(null, true)),
    uncompressed: Buffer.from(publicKey.encode(null, false))
  }
}

export function getSignature (message, privateKey) {
  return sign(message, privateKey).signatureLowS
}

export function getTweak () {
  while (true) {
    const tweak = prngs.tweak.randomBytes(32)
    const bn = new BN(tweak)
    if (bn.cmp(ec.curve.n) === -1) return tweak
  }
}

export function getMessage () {
  return prngs.message.randomBytes(32)
}

export function sign (message, privateKey) {
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

  return { signature, signatureLowS, recovery }
}

export function ecdhSHA256x (publicKey, privateKey) {
  const secret = ec.keyFromPrivate(privateKey)
  const point = ec.keyFromPublic(publicKey).getPublic()
  const sharedSecret = Buffer.from(point.mul(secret.priv).encode(null, true))
  return createHash('sha256').update(sharedSecret).digest()
}

export function ecdhUnsafe (publicKey, privateKey) {
  const secret = ec.keyFromPrivate(privateKey)
  const point = ec.keyFromPublic(publicKey).getPublic()
  const shared = point.mul(secret.priv)
  return {
    compressed: Buffer.from(shared.encode(null, true)),
    uncompressed: Buffer.from(shared.encode(null, false))
  }
}

export const env = {
  EDGE_ONLY: (global.__env__ && global.__env__.EDGE_ONLY ||
              process.env.EDGE_ONLY ||
              'true') === 'true',
  REPEAT: parseInt(global.__env__ && global.__env__.RANDOM_TESTS_REPEAT ||
                   process.env.RANDOM_TESTS_REPEAT ||
                   100,
                   10),
  SEED: global.__env__ && global.__env__.SEED ||
        process.env.SEED ||
        randomBytes(32)
}

export function repeat (t, name, total, fn) { _repeat(t.test, name, total, fn) }
repeat.skip = function (t, name, total, fn) { _repeat(t.skip, name, total, fn) }
repeat.only = function (t, name, total, fn) { _repeat(t.only, name, total, fn) }

function _repeat (test, name, total, fn) {
  test(name, function (t) {
    const _end = t.end
    let curr = 0

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
