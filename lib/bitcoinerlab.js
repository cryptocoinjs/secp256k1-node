const secp256k1 = require('@bitcoinerlab/secp256k1')

const errors = {
  EXPECTED_PRIVATE: 'Expected Private',
  EXPECTED_POINT: 'Expected Point',
  EXPECTED_SIGNATURE: 'Expected Signature'
}

// Pre-load elliptic as a backup
const elliptic = require('./elliptic')

function isCompressedPublicKey (array) {
  return array.length === 33
}

module.exports = {
  contextRandomize: function () {
    // Historically served to randomize the context in constant time, RNG is sufficiently randomized internally.
    return 0
  },
  privateKeyVerify: function (privateKey) {
    return secp256k1.isPrivate(privateKey) ? 0 : 1
  },
  privateKeyNegate: function (privateKey) {
    try {
      const res = secp256k1.privateNegate(privateKey)
      if (!res) return 1
      privateKey.set(res)
    } catch (e) {
      elliptic.privateKeyNegate(privateKey)
    }
    return 0
  },
  privateKeyTweakAdd: function (privateKey, tweak) {
    try {
      const res = secp256k1.privateAdd(privateKey, tweak)
      if (!res) return 1
      privateKey.set(res)
    } catch (e) {
      return 1
    }
    return 0
  },
  privateKeyTweakMul: function (privateKey, tweak) {
    return elliptic.privateKeyTweakMul(privateKey, tweak)
  },
  publicKeyVerify: function (publicKey) {
    return secp256k1.isPoint(publicKey) ? 0 : 1
  },
  publicKeyCreate: function (output, seckey) {
    try {
      const res = secp256k1.pointFromScalar(seckey, isCompressedPublicKey(output))
      if (!res) return 2
      output.set(res)
      return 0
    } catch (e) {
      return 1
    }
  },
  publicKeyConvert: function (output, pubkey) {
    try {
      output.set(secp256k1.pointCompress(pubkey, isCompressedPublicKey(output)))
      return 0
    } catch (e) {
      if (e.message === errors.EXPECTED_POINT) return 1
      return 2
    }
  },
  publicKeyNegate: function (output, pubkey) {
    return elliptic.publicKeyNegate(output, pubkey)
  },
  publicKeyCombine: function (output, pubkeys) {
    return elliptic.publicKeyCombine(output, pubkeys)
  },
  publicKeyTweakAdd: function (output, pubkey, tweak) {
    try {
      const res = secp256k1.pointAddScalar(pubkey, tweak, isCompressedPublicKey(output))
      if (!res) return 2
      output.set(res)
      return 0
    } catch (e) {
      if (e.message === errors.EXPECTED_POINT) return 1
      return 2
    }
  },
  publicKeyTweakMul: function (output, pubkey, tweak) {
    try {
      const res = secp256k1.pointMultiply(pubkey, tweak, isCompressedPublicKey(output))
      if (!res) return 2
      output.set(res)
      return 0
    } catch (e) {
      if (e.message === errors.EXPECTED_POINT) return 1
      return 2
    }
  },
  signatureNormalize: function (sig) {
    return elliptic.signatureNormalize(sig)
  },
  signatureExport: function (obj, sig) {
    return elliptic.signatureExport(obj, sig)
  },
  signatureImport: function (output, sig) {
    return elliptic.signatureImport(output, sig)
  },
  ecdsaSign: function (obj, msg32, seckey, data, noncefn) {
    if (noncefn) {
      return elliptic.ecdsaSign(obj, msg32, seckey, data, noncefn)
    }
    try {
      obj.signature.set(secp256k1.sign(msg32, seckey, data))
      Object.defineProperty(obj, 'recid', {
        get: function () {
          const obj = { signature: this.signature, recid: null }
          elliptic.ecdsaSign(obj, msg32, seckey, data, noncefn)
          return obj.recid
        }
      })
      return 0
    } catch (e) {
      if (e.message === errors.EXPECTED_PRIVATE) return 1
      return 2
    }
  },
  ecdsaVerify: function (signature, message, publicKey) {
    try {
      return secp256k1.verify(message, publicKey, signature) ? 0 : 3
    } catch (e) {
      if (e.message === errors.EXPECTED_SIGNATURE) return 1
      return 2
    }
  },
  ecdsaRecover: function (output, sig, recid, msg32) {
    return elliptic.ecdsaRecover(output, sig, recid, msg32)
  },
  ecdh: function (output, pubkey, seckey, data, hashfn, xbuf, ybuf) {
    return elliptic.ecdh(output, pubkey, seckey, data, hashfn, xbuf, ybuf)
  }
}
