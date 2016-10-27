import * as der from './der'
import * as util from './util'
import * as messages from './messages.json'

export function privateKey (impl) {
  return {
    verify: (privateKey) => {
      util.checkTypeBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID)
      return privateKey.length === 32 && impl.verify(privateKey)
    },

    export: (privateKey, compressed = true) => {
      util.handleArgPrivateKey(privateKey)
      util.handleArgCompressed(compressed)

      const publicKey = impl.export(privateKey, compressed)
      return der.privateKey.export(privateKey, publicKey, compressed)
    },

    import: (privateKey) => {
      util.checkTypeBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID)
      util.checkLengthGTZero(privateKey, messages.EC_PRIVATE_KEY_LENGTH_INVALID)

      privateKey = der.privateKey.import(privateKey)
      if (privateKey && privateKey.length === 32 && impl.verify(privateKey)) return privateKey

      throw new Error(messages.EC_PRIVATE_KEY_IMPORT_DER_FAIL)
    },

    tweakAdd: (privateKey, tweak) => {
      util.handleArgPrivateKey(privateKey)
      util.handleArgTweak(tweak)

      return impl.tweakAdd(privateKey, tweak)
    },

    tweakMul: (privateKey, tweak) => {
      util.handleArgPrivateKey(privateKey)
      util.handleArgTweak(tweak)

      return impl.tweakMul(privateKey, tweak)
    }
  }
}

export function publicKey (impl) {
  return {
    create: (privateKey, compressed = true) => {
      util.handleArgPrivateKey(privateKey)
      util.handleArgCompressed(compressed)

      return impl.create(privateKey, compressed)
    },

    convert: (publicKey, compressed = true) => {
      util.handleArgPublicKey(publicKey)
      util.handleArgCompressed(compressed)

      return impl.convert(publicKey, compressed)
    },

    verify: (publicKey) => {
      util.checkTypeBuffer(publicKey, messages.EC_PUBLIC_KEY_TYPE_INVALID)
      return impl.verify(publicKey)
    },

    tweakAdd: (publicKey, tweak, compressed = true) => {
      util.handleArgPublicKey(publicKey)
      util.handleArgTweak(tweak)
      util.handleArgCompressed(compressed)

      return impl.tweakAdd(publicKey, tweak, compressed)
    },

    tweakMul: (publicKey, tweak, compressed = true) => {
      util.handleArgPublicKey(publicKey)
      util.handleArgTweak(tweak)
      util.handleArgCompressed(compressed)

      return impl.tweakMul(publicKey, tweak, compressed)
    },

    combine: (publicKeys, compressed = true) => {
      util.checkTypeArray(publicKeys, messages.EC_PUBLIC_KEYS_TYPE_INVALID)
      util.checkLengthGTZero(publicKeys, messages.EC_PUBLIC_KEYS_LENGTH_INVALID)
      for (let i = 0; i < publicKeys.length; ++i) util.handleArgPublicKey(publicKeys[i])
      util.handleArgCompressed(compressed)

      return impl.combine(publicKeys, compressed)
    }
  }
}

export function ecdsa (impl) {
  return {
    signature: {
      normalize: (signature) => {
        util.handleArgECDSASignatureRaw(signature)
        return impl.signature.normalize(signature)
      },

      export: (signature) => {
        util.handleArgECDSASignatureRaw(signature)

        const sigObj = impl.signature.export(signature)
        return der.signature.export(sigObj)
      },

      import: (signature) => {
        util.handleArgECDSASignatureDer(signature)

        const sigObj = der.signature.import(signature)
        if (sigObj) return impl.signature.import(sigObj)

        throw new Error(messages.ECDSA_SIGNATURE_PARSE_DER_FAIL)
      },

      importLax: (signature) => {
        util.handleArgECDSASignatureDer(signature)

        const sigObj = der.signature.importLax(signature)
        if (sigObj) return impl.signature.import(sigObj)

        throw new Error(messages.ECDSA_SIGNATURE_PARSE_DER_FAIL)
      }
    },

    sign: (message, privateKey, noncefn, noncedata) => {
      util.handleArgMessage(message)
      util.handleArgPrivateKey(privateKey)
      util.handleArgNonceFunction(noncefn)
      util.handleArgNonceData(noncedata)

      return impl.sign(message, privateKey, noncefn, noncedata)
    },

    verify: (signature, message, publicKey) => {
      util.handleArgECDSASignatureRaw(signature)
      util.handleArgMessage(message)
      util.handleArgPublicKey(publicKey)

      return impl.verify(signature, message, publicKey)
    },

    recover: (signature, recovery, message, compressed = true) => {
      util.handleArgECDSASignatureRaw(signature)
      util.checkTypeNumber(recovery, messages.ECDSA_RECOVERY_ID_TYPE_INVALID)
      util.checkInInterval(recovery, 0, 3, messages.ECDSA_RECOVERY_ID_VALUE_INVALID)
      util.handleArgMessage(message)
      util.handleArgCompressed(compressed)

      return impl.recover(signature, recovery, message, compressed)
    }
  }
}

export function schnorr (impl) {
  return {
    sign: (message, privateKey, noncefn, noncedata) => {
      util.handleArgMessage(message)
      util.handleArgPrivateKey(privateKey)
      util.handleArgNonceFunction(noncefn)
      util.handleArgNonceData(noncedata)

      return impl.sign(message, privateKey, noncefn, noncedata)
    },

    verify: (signature, message, publicKey) => {
      util.handleArgSchnorrSignature(signature)
      util.handleArgMessage(message)
      util.handleArgPublicKey(publicKey)

      return impl.verify(signature, message, publicKey)
    },

    recover: (signature, message, compressed = true) => {
      util.handleArgSchnorrSignature(signature)
      util.handleArgMessage(message)
      util.handleArgCompressed(compressed)

      return impl.recover(signature, message, compressed)
    },

    generateNoncePair: (message, privateKey, noncefn, noncedata, compressed = true) => {
      util.handleArgMessage(message)
      util.handleArgPrivateKey(privateKey)
      util.handleArgNonceFunction(noncefn)
      util.handleArgNonceData(noncedata)
      util.handleArgCompressed(compressed)

      return impl.generateNoncePair(message, privateKey, noncefn, noncedata, compressed)
    },

    partialSign: (message, privateKey, pubnonce, privnonce) => {
      util.handleArgMessage(message)
      util.handleArgPrivateKey(privateKey)
      util.handleArgPublicKey(pubnonce)
      util.handleArgPrivateKey(privnonce)

      return impl.partialSign(message, privateKey, pubnonce, privnonce)
    },

    partialCombine: (signatures) => {
      util.checkTypeArray(signatures, messages.SCHNORR_SIGNATURES_TYPE_INVALID)
      util.checkLengthGTZero(signatures, messages.SCHNORR_SIGNATURES_LENGTH_INVALID)
      for (let i = 0; i < signatures.length; ++i) util.handleArgSchnorrSignature(signatures[i])

      return impl.combine(signatures)
    }
  }
}

export function ecdh (impl) {
  return {
    sha256: (publicKey, privateKey) => {
      util.handleArgPublicKey(publicKey)
      util.handleArgPrivateKey(privateKey)

      return impl.sha256(publicKey, privateKey)
    },

    unsafe: (publicKey, privateKey, compressed = true) => {
      util.handleArgPublicKey(publicKey)
      util.handleArgPrivateKey(privateKey)
      util.handleArgCompressed(compressed)

      return impl.unsafe(publicKey, privateKey, compressed)
    }
  }
}
