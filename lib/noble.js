'use strict'

const { secp256k1: curve } = require('@noble/curves/secp256k1')
const { createHash } = require('crypto')

const N = curve.CURVE.n
const { ProjectivePoint } = curve

// Uint8Array → BigInt (big-endian)
function u8ToBigInt (u8) {
  let hex = ''
  for (let i = 0; i < u8.length; i++) hex += u8[i].toString(16).padStart(2, '0')
  return BigInt('0x' + hex)
}

// BigInt → Uint8Array, big-endian, fixed length
function bigIntToU8 (n, length = 32) {
  const hex = n.toString(16).padStart(length * 2, '0')
  const out = new Uint8Array(length)
  for (let i = 0; i < length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

function sha256 (data) {
  return new Uint8Array(createHash('sha256').update(data).digest())
}

module.exports = {
  contextRandomize () {
    return 0
  },

  privateKeyVerify (seckey) {
    try {
      return curve.utils.isValidPrivateKey(seckey) ? 0 : 1
    } catch {
      return 1
    }
  },

  privateKeyNegate (seckey) {
    try {
      // (N - (bn mod N)) mod N handles 0, N, and overflow inputs correctly
      const bn = u8ToBigInt(seckey)
      seckey.set(bigIntToU8((N - (bn % N)) % N))
      return 0
    } catch {
      return 1
    }
  },

  privateKeyTweakAdd (seckey, tweak) {
    try {
      const t = u8ToBigInt(tweak)
      if (t >= N) return 1
      const result = (u8ToBigInt(seckey) + t) % N
      if (result === 0n) return 1
      seckey.set(bigIntToU8(result))
      return 0
    } catch {
      return 1
    }
  },

  privateKeyTweakMul (seckey, tweak) {
    try {
      const t = u8ToBigInt(tweak)
      if (t === 0n || t >= N) return 1
      const result = (u8ToBigInt(seckey) * t) % N
      seckey.set(bigIntToU8(result))
      return 0
    } catch {
      return 1
    }
  },

  publicKeyVerify (pubkey) {
    try {
      ProjectivePoint.fromHex(pubkey)
      return 0
    } catch {
      return 1
    }
  },

  publicKeyCreate (output, seckey) {
    try {
      const pub = curve.getPublicKey(seckey, output.length === 33)
      output.set(pub)
      return 0
    } catch {
      return 1
    }
  },

  publicKeyConvert (output, pubkey) {
    try {
      const point = ProjectivePoint.fromHex(pubkey)
      output.set(point.toRawBytes(output.length === 33))
      return 0
    } catch {
      return 1
    }
  },

  publicKeyNegate (output, pubkey) {
    try {
      const point = ProjectivePoint.fromHex(pubkey)
      output.set(point.negate().toRawBytes(output.length === 33))
      return 0
    } catch {
      return 1
    }
  },

  publicKeyCombine (output, pubkeys) {
    try {
      let point = ProjectivePoint.fromHex(pubkeys[0])
      for (let i = 1; i < pubkeys.length; i++) {
        point = point.add(ProjectivePoint.fromHex(pubkeys[i]))
      }
      if (point.equals(ProjectivePoint.ZERO)) return 2
      output.set(point.toRawBytes(output.length === 33))
      return 0
    } catch {
      return 1
    }
  },

  publicKeyTweakAdd (output, pubkey, tweak) {
    try {
      const t = u8ToBigInt(tweak)
      if (t >= N) return 2
      const point = ProjectivePoint.fromHex(pubkey)
      const tweaked = point.add(ProjectivePoint.BASE.multiply(t))
      if (tweaked.equals(ProjectivePoint.ZERO)) return 2
      output.set(tweaked.toRawBytes(output.length === 33))
      return 0
    } catch {
      return 1
    }
  },

  publicKeyTweakMul (output, pubkey, tweak) {
    try {
      const t = u8ToBigInt(tweak)
      if (t === 0n || t >= N) return 2
      const point = ProjectivePoint.fromHex(pubkey)
      output.set(point.multiply(t).toRawBytes(output.length === 33))
      return 0
    } catch {
      return 1
    }
  },

  signatureNormalize (sig) {
    try {
      const r = u8ToBigInt(sig.subarray(0, 32))
      const s = u8ToBigInt(sig.subarray(32, 64))
      if (r >= N || s >= N) return 1
      // Low-S normalisation
      if (s > N >> 1n) sig.set(bigIntToU8(N - s), 32)
      return 0
    } catch {
      return 1
    }
  },

  signatureExport (obj, sig) {
    try {
      const r = u8ToBigInt(sig.subarray(0, 32))
      const s = u8ToBigInt(sig.subarray(32, 64))
      if (r >= N || s >= N) return 1
      const der = new curve.Signature(r, s).toDERRawBytes()
      obj.outputlen = der.length
      obj.output.set(der)
      return 0
    } catch {
      return 1
    }
  },

  signatureImport (output, sig) {
    try {
      const compact = curve.Signature.fromDER(sig).toCompactRawBytes()
      output.set(compact)
      return 0
    } catch {
      return 1
    }
  },

  ecdsaSign (obj, message, seckey, data, noncefn) {
    try {
      // Noble uses RFC6979 deterministic nonce by default. Custom noncefn is
      // not directly supported; extraEntropy approximates it for test vectors.
      let extraEntropy
      if (noncefn) {
        const nonce = noncefn(message, seckey, null, data, 0)
        if (!(nonce instanceof Uint8Array) || nonce.length !== 32) return 1
        extraEntropy = nonce
      }

      const sig = curve.sign(message, seckey, { lowS: true, extraEntropy })
      obj.signature.set(sig.toCompactRawBytes())
      obj.recid = sig.recovery
      return 0
    } catch {
      return 1
    }
  },

  ecdsaVerify (sig, msg32, pubkey) {
    try {
      const r = u8ToBigInt(sig.subarray(0, 32))
      const s = u8ToBigInt(sig.subarray(32, 64))
      if (r >= N || s >= N) return 1
      if (r === 0n || s === 0n || s > N >> 1n) return 3 // zero r/s or high-S

      try {
        ProjectivePoint.fromHex(pubkey)
      } catch {
        return 2
      }

      const valid = curve.verify(new curve.Signature(r, s), msg32, pubkey, { lowS: true })
      return valid ? 0 : 3
    } catch {
      return 1
    }
  },

  ecdsaRecover (output, sig, recid, msg32) {
    try {
      const r = u8ToBigInt(sig.subarray(0, 32))
      const s = u8ToBigInt(sig.subarray(32, 64))
      if (r >= N || s >= N) return 1
      if (r === 0n || s === 0n) return 2

      const recovered = new curve.Signature(r, s, recid)
        .recoverPublicKey(msg32)
      output.set(recovered.toRawBytes(output.length === 33))
      return 0
    } catch {
      return 2
    }
  },

  ecdh (output, pubkey, seckey, data, hashfn, xbuf, ybuf) {
    try {
      const scalar = u8ToBigInt(seckey)
      if (scalar === 0n || scalar >= N) return 2

      const point = ProjectivePoint.fromHex(pubkey).multiply(scalar)

      if (hashfn === undefined) {
        // Default: SHA256 of compressed shared point (matches secp256k1 spec)
        output.set(sha256(point.toRawBytes(true)))
      } else {
        if (!xbuf) xbuf = new Uint8Array(32)
        if (!ybuf) ybuf = new Uint8Array(32)
        xbuf.set(bigIntToU8(point.x))
        ybuf.set(bigIntToU8(point.y))
        const hash = hashfn(xbuf, ybuf, data)
        if (!(hash instanceof Uint8Array) || hash.length !== output.length) return 2
        output.set(hash)
      }

      return 0
    } catch {
      return 1
    }
  }
}
