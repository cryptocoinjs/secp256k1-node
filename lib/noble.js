const secp256k1 = require('@noble/secp256k1')
const { sha256 } = require('@noble/hashes/sha256')
const { hmac } = require('@noble/hashes/hmac')

/* global BigInt */

if (!secp256k1.utils.hmacSha256Sync) {
  secp256k1.utils.hmacSha256Sync = (key, ...msgs) => hmac(sha256, key, secp256k1.utils.concatBytes(...msgs))
}
if (!secp256k1.utils.sha256Sync) {
  secp256k1.utils.sha256Sync = (...msgs) => sha256(secp256k1.utils.concatBytes(...msgs))
}

function writePublicKey (output, point) {
  const buf = point.toRawBytes(output.length === 33)
  if (output.length !== buf.length) return 1
  output.set(buf)
  return 0
}

function toBig (arr) {
  // args already typechecked in ./lib/index.js
  return BigInt('0x' + secp256k1.utils.bytesToHex(arr))
}

const _0n = BigInt(0)
const _1n = BigInt(1)

let elliptic // used for signing with nonce function and/or non-32 byte extra entropy data

module.exports = {
  contextRandomize () {
    return 0
  },

  privateKeyVerify (seckey) {
    return secp256k1.utils.isValidPrivateKey(seckey) ? 0 : 1
  },

  // Validation matches ./elliptic.js
  // Doesn't fail on out of bounds values, normalize them
  privateKeyNegate (seckey) {
    const res = secp256k1.utils.mod(secp256k1.CURVE.n - toBig(seckey), secp256k1.CURVE.n)

    const buf = secp256k1.utils._bigintTo32Bytes(res)
    seckey.set(buf)

    return 0
  },

  // Validation matches ./elliptic.js
  privateKeyTweakAdd (seckey, tweak) {
    let res = toBig(tweak)
    if (res >= secp256k1.CURVE.n) return 1

    res = secp256k1.utils.mod(res + toBig(seckey), secp256k1.CURVE.n)
    if (res === _0n) return 1

    const buf = secp256k1.utils._bigintTo32Bytes(res)
    seckey.set(buf)

    return 0
  },

  // Validation matches ./elliptic.js
  privateKeyTweakMul (seckey, tweak) {
    let res = toBig(tweak)
    if (res >= secp256k1.CURVE.n || res === 0n) return 1

    res = secp256k1.utils.mod(res * toBig(seckey), secp256k1.CURVE.n)

    const buf = secp256k1.utils._bigintTo32Bytes(res)
    seckey.set(buf)

    return 0
  },

  publicKeyVerify (pubkey) {
    try {
      return secp256k1.Point.fromHex(pubkey) ? 0 : 1
    } catch (err) {
      return 1
    }
  },

  publicKeyCreate (output, seckey) {
    try {
      const publicKey = secp256k1.getPublicKey(seckey, output.length === 33)
      if (output.length !== publicKey.length) return 1
      output.set(publicKey)
      return 0
    } catch (err) {
      return 1
    }
  },

  publicKeyConvert (output, pubkey) {
    try {
      const publicKey = secp256k1.Point.fromHex(pubkey).toRawBytes(output.length === 33)
      if (output.length !== publicKey.length) return 1
      output.set(publicKey)
      return 0
    } catch (err) {
      return 1
    }
  },

  publicKeyNegate (output, pubkey) {
    let P
    try {
      P = secp256k1.Point.fromHex(pubkey)
    } catch (err) {
      return 1
    }

    const point = P.negate()
    return writePublicKey(output, point)
  },

  publicKeyCombine (output, pubkeys) {
    const points = new Array(pubkeys.length)
    for (let i = 0; i < pubkeys.length; ++i) {
      try {
        points[i] = secp256k1.Point.fromHex(pubkeys[i])
      } catch (err) {
        return 1
      }
    }

    let point = points[0]
    for (let i = 1; i < points.length; ++i) point = point.add(points[i])
    if (point.equals(secp256k1.Point.ZERO)) return 2
    return writePublicKey(output, point)
  },

  publicKeyTweakAdd (output, pubkey, tweak) {
    let P
    try {
      P = secp256k1.Point.fromHex(pubkey)
    } catch (err) {
      return 1
    }

    tweak = toBig(tweak)
    if (tweak >= secp256k1.CURVE.n) return 2

    // returns a non-zero point or undefined
    const point = secp256k1.Point.BASE.multiplyAndAddUnsafe(P, tweak, _1n) // timing-unsafe, ok here
    if (!point) return 2 // returns undefined on ZERO
    return writePublicKey(output, point)
  },

  publicKeyTweakMul (output, pubkey, tweak) {
    let P
    try {
      P = secp256k1.Point.fromHex(pubkey)
    } catch (err) {
      return 1
    }

    tweak = toBig(tweak)
    if (tweak >= secp256k1.CURVE.n || tweak === _0n) return 2

    const point = P.multiply(tweak)
    if (point.equals(secp256k1.Point.ZERO)) return 2
    return writePublicKey(output, point)
  },

  signatureNormalize (sig) {
    try {
      const signature = secp256k1.Signature.fromCompact(sig)
      if (signature.hasHighS()) {
        const normal = signature.normalizeS().toCompactRawBytes()
        sig.set(normal.subarray(32), 32)
      }
    } catch (err) {
      return 1
    }

    return 0
  },

  signatureExport (obj, sig) {
    let der
    try {
      der = secp256k1.Signature.fromCompact(sig).toDERRawBytes()
    } catch (err) {
      return 1
    }

    if (obj.output.length < der.length) return 1

    obj.output.set(der)
    obj.outputlen = der.length
    return 0
  },

  signatureImport (output, sig) {
    let buf
    try {
      buf = secp256k1.Signature.fromDER(sig).toCompactRawBytes()
    } catch (err) {
      return 1
    }

    if (output.length !== buf.length) return 1
    output.set(buf)
    return 0
  },

  ecdsaSign (obj, message, seckey, data, noncefn) {
    if (noncefn || (data && data.length !== 32)) {
      // Can we deprecate noncefn & drop it in next major? Also non-32 byte data
      if (!elliptic) elliptic = require('./elliptic.js')
      return elliptic.ecdsaSign(obj, message, seckey, data, noncefn)
    }

    let sig
    try {
      sig = secp256k1.signSync(message, seckey, { der: false, recovered: true, extraEntropy: data })
    } catch (err) {
      return 1
    }

    if (obj.signature.length !== sig[0].length) return 1
    obj.signature.set(sig[0])
    obj.recid = sig[1]
    return 0
  },

  // Complex logic to return correct error codes
  ecdsaVerify (sig, msg32, pubkey) {
    if (sig.subarray(0, 32).every((x) => x === 0)) return 3
    if (sig.subarray(32, 64).every((x) => x === 0)) return 3

    let signature
    try {
      signature = secp256k1.Signature.fromCompact(sig)
    } catch (err) {
      return 1
    }
    if (signature.hasHighS()) return 3

    let pub
    try {
      pub = secp256k1.Point.fromHex(pubkey)
    } catch (err) {
      return 2
    }

    return secp256k1.verify(sig, msg32, pub) ? 0 : 3
  },

  // Complex logic to return correct error codes
  ecdsaRecover (output, sig, recid, msg32) {
    if (sig.subarray(0, 32).every((x) => x === 0)) return 2
    if (sig.subarray(32, 64).every((x) => x === 0)) return 2

    let signature
    try {
      signature = secp256k1.Signature.fromCompact(sig)
    } catch (err) {
      return 1
    }

    let buf
    try {
      buf = secp256k1.recoverPublicKey(msg32, signature, recid, output.length === 33)
    } catch (err) {
      return 2
    }

    if (output.length !== buf.length) return 1
    output.set(buf)
    return 0
  },

  ecdh (output, pubkey, seckey, data, hashfn, xbuf, ybuf) {
    let pub
    try {
      pub = secp256k1.Point.fromHex(pubkey)
    } catch (err) {
      return 1
    }

    const compressed = hashfn === undefined

    let point
    try {
      point = secp256k1.getSharedSecret(seckey, pub, compressed)
    } catch (err) {
      return 2
    }

    if (hashfn === undefined) {
      output.set(sha256(point))
    } else {
      if (!xbuf) xbuf = new Uint8Array(32)
      xbuf.set(point.subarray(1, 33))

      if (!ybuf) ybuf = new Uint8Array(32)
      ybuf.set(point.subarray(33))

      const hash = hashfn(xbuf, ybuf, data)
      const isValid = hash instanceof Uint8Array && hash.length === output.length
      if (!isValid) return 2

      output.set(hash)
    }

    return 0
  }
}
