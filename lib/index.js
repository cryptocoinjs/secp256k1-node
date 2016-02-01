'use strict'

var assert = require('./assert')
var messages = require('./messages.json')

var EC_PRIVKEY_EXPORT_DER_COMPRESSED_BEGIN = new Buffer(
  '3081d30201010420', 'hex')
var EC_PRIVKEY_EXPORT_DER_COMPRESSED_MIDDLE = new Buffer(
  'a08185308182020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f300604010004010704210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101a124032200', 'hex')
var EC_PRIVKEY_EXPORT_DER_UNCOMPRESSED_BEGIN = new Buffer(
  '308201130201010420', 'hex')
var EC_PRIVKEY_EXPORT_DER_UNCOMPRESSED_MIDDLE = new Buffer(
  'a081a53081a2020101302c06072a8648ce3d0101022100fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f300604010004010704410479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8022100fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141020101a144034200', 'hex')

/**
 * @param {*} value
 * @param {boolean} defaultValue
 * @return {boolean}
 */
function initCompressedValue (value, defaultValue) {
  if (value === undefined) {
    return defaultValue
  }

  assert.isBoolean(value, messages.COMPRESSED_TYPE_INVALID)
  return value
}

/**
 * @param {Object} o
 * @param {Buffer} o.sig
 * @param {number} o.idx
 * @return {?Buffer}
 */
function parseScalar (o) {
  if (o.sig[o.idx++] !== 0x02) {
    return null
  }

  var rlen = o.sig[o.idx++]
  if (rlen === 0 || rlen > 33 ||
      (rlen > 1 &&
       (o.sig[o.idx] === 0x00 && o.sig[o.idx + 1] < 0x80) ||
       (o.sig[o.idx] === 0xff && o.sig[o.idx + 1] >= 0x80))) {
    return null
  }

  if (o.sig[o.idx] === 0 && rlen === 33) {
    o.idx += 1
    rlen -= 1
  }

  o.idx += rlen

  var result = new Buffer(32)
  result.fill(0)

  if (rlen <= 32) {
    o.sig.slice(o.idx - rlen, o.idx).copy(result, 32 - rlen)
  }

  return result
}

/**
 * @param {Object} secp256k1
 * @return {Object}
 */
module.exports = function (secp256k1) {
  return {
    /**
     * @param {Buffer} privateKey
     * @return {boolean}
     */
    privateKeyVerify: function (privateKey) {
      assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID)
      return privateKey.length === 32 && secp256k1.privateKeyVerify(privateKey)
    },

    /**
     * @param {Buffer} privateKey
     * @param {boolean} [compressed=true]
     * @return {Buffer}
     */
    privateKeyExport: function (privateKey, compressed) {
      assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID)
      assert.isBufferLength(privateKey, 32, messages.EC_PRIVATE_KEY_LENGTH_INVALID)

      compressed = initCompressedValue(compressed, true)

      var publicKey = secp256k1.privateKeyExport(privateKey, compressed)

      var result = new Buffer(compressed ? 214 : 279)
      var targetStart = 0
      if (compressed) {
        EC_PRIVKEY_EXPORT_DER_COMPRESSED_BEGIN.copy(result, targetStart)
        targetStart += EC_PRIVKEY_EXPORT_DER_COMPRESSED_BEGIN.length

        privateKey.copy(result, targetStart)
        targetStart += privateKey.length

        EC_PRIVKEY_EXPORT_DER_COMPRESSED_MIDDLE.copy(result, targetStart)
        targetStart += EC_PRIVKEY_EXPORT_DER_COMPRESSED_MIDDLE.length

        publicKey.copy(result, targetStart)
      } else {
        EC_PRIVKEY_EXPORT_DER_UNCOMPRESSED_BEGIN.copy(result, targetStart)
        targetStart += EC_PRIVKEY_EXPORT_DER_UNCOMPRESSED_BEGIN.length

        privateKey.copy(result, targetStart)
        targetStart += privateKey.length

        EC_PRIVKEY_EXPORT_DER_UNCOMPRESSED_MIDDLE.copy(result, targetStart)
        targetStart += EC_PRIVKEY_EXPORT_DER_UNCOMPRESSED_MIDDLE.length

        publicKey.copy(result, targetStart)
      }

      return result
    },

    /**
     * @param {Buffer} privateKey
     * @return {Buffer}
     */
    privateKeyImport: function (privateKey) {
      assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID)

      do {
        var length = privateKey.length

        // sequence header
        var index = 0
        if (length < index + 1 || privateKey[index] !== 0x30) {
          break
        }
        index += 1

        // sequence length constructor
        if (length < index + 1 || !(privateKey[index] & 0x80)) {
          break
        }

        var lenb = privateKey[index] & 0x7f
        index += 1
        if (lenb < 1 || lenb > 2) {
          break
        }
        if (length < index + lenb) {
          break
        }

        // sequence length
        var len = privateKey[index + lenb - 1] | (lenb > 1 ? privateKey[index + lenb - 2] << 8 : 0)
        index += lenb
        if (length < index + len) {
          break
        }

        // sequence element 0: version number (=1)
        if (length < index + 3 ||
            privateKey[index] !== 0x02 ||
            privateKey[index + 1] !== 0x01 ||
            privateKey[index + 2] !== 0x01) {
          break
        }
        index += 3

        // sequence element 1: octet string, up to 32 bytes
        if (length < index + 2 ||
            privateKey[index] !== 0x04 ||
            privateKey[index + 1] > 0x20 ||
            length < index + 2 + privateKey[index + 1]) {
          break
        }

        privateKey = privateKey.slice(index + 2, index + 2 + privateKey[index + 1])
        if (privateKey.length === 32 && secp256k1.privateKeyVerify(privateKey)) {
          return privateKey
        }
      } while (false)

      throw new Error(messages.EC_PRIVATE_KEY_IMPORT_DER_FAIL)
    },

    /**
     * @param {Buffer} privateKey
     * @param {Buffer} tweak
     * @return {Buffer}
     */
    privateKeyTweakAdd: function (privateKey, tweak) {
      assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID)
      assert.isBufferLength(privateKey, 32, messages.EC_PRIVATE_KEY_LENGTH_INVALID)

      assert.isBuffer(tweak, messages.TWEAK_TYPE_INVALID)
      assert.isBufferLength(tweak, 32, messages.TWEAK_LENGTH_INVALID)

      return secp256k1.privateKeyTweakAdd(privateKey, tweak)
    },

    /**
     * @param {Buffer} privateKey
     * @param {Buffer} tweak
     * @return {Buffer}
     */
    privateKeyTweakMul: function (privateKey, tweak) {
      assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID)
      assert.isBufferLength(privateKey, 32, messages.EC_PRIVATE_KEY_LENGTH_INVALID)

      assert.isBuffer(tweak, messages.TWEAK_TYPE_INVALID)
      assert.isBufferLength(tweak, 32, messages.TWEAK_LENGTH_INVALID)

      return secp256k1.privateKeyTweakMul(privateKey, tweak)
    },

    /**
     * @param {Buffer} privateKey
     * @param {boolean} [compressed=true]
     * @return {Buffer}
     */
    publicKeyCreate: function (privateKey, compressed) {
      assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID)
      assert.isBufferLength(privateKey, 32, messages.EC_PRIVATE_KEY_LENGTH_INVALID)

      compressed = initCompressedValue(compressed, true)

      return secp256k1.publicKeyCreate(privateKey, compressed)
    },

    /**
     * @param {Buffer} publicKey
     * @param {boolean} [compressed=true]
     * @return {Buffer}
     */
    publicKeyConvert: function (publicKey, compressed) {
      assert.isBuffer(publicKey, messages.EC_PUBLIC_KEY_TYPE_INVALID)
      assert.isBufferLength2(publicKey, 33, 65, messages.EC_PUBLIC_KEY_LENGTH_INVALID)

      compressed = initCompressedValue(compressed, true)

      return secp256k1.publicKeyConvert(publicKey, compressed)
    },

    /**
     * @param {Buffer} publicKey
     * @return {boolean}
     */
    publicKeyVerify: function (publicKey) {
      assert.isBuffer(publicKey, messages.EC_PUBLIC_KEY_TYPE_INVALID)
      return secp256k1.publicKeyVerify(publicKey)
    },

    /**
     * @param {Buffer} publicKey
     * @param {Buffer} tweak
     * @param {boolean} [compressed=true]
     * @return {Buffer}
     */
    publicKeyTweakAdd: function (publicKey, tweak, compressed) {
      assert.isBuffer(publicKey, messages.EC_PUBLIC_KEY_TYPE_INVALID)
      assert.isBufferLength2(publicKey, 33, 65, messages.EC_PUBLIC_KEY_LENGTH_INVALID)

      assert.isBuffer(tweak, messages.TWEAK_TYPE_INVALID)
      assert.isBufferLength(tweak, 32, messages.TWEAK_LENGTH_INVALID)

      compressed = initCompressedValue(compressed, true)

      return secp256k1.publicKeyTweakAdd(publicKey, tweak, compressed)
    },

    /**
     * @param {Buffer} publicKey
     * @param {Buffer} tweak
     * @param {boolean} [compressed=true]
     * @return {Buffer}
     */
    publicKeyTweakMul: function (publicKey, tweak, compressed) {
      assert.isBuffer(publicKey, messages.EC_PUBLIC_KEY_TYPE_INVALID)
      assert.isBufferLength2(publicKey, 33, 65, messages.EC_PUBLIC_KEY_LENGTH_INVALID)

      assert.isBuffer(tweak, messages.TWEAK_TYPE_INVALID)
      assert.isBufferLength(tweak, 32, messages.TWEAK_LENGTH_INVALID)

      compressed = initCompressedValue(compressed, true)

      return secp256k1.publicKeyTweakMul(publicKey, tweak, compressed)
    },

    /**
     * @param {Buffer[]} publicKeys
     * @param {boolean} [compressed=true]
     * @return {Buffer}
     */
    publicKeyCombine: function (publicKeys, compressed) {
      assert.isArray(publicKeys, messages.EC_PUBLIC_KEYS_TYPE_INVALID)
      assert.isLengthGTZero(publicKeys, messages.EC_PUBLIC_KEYS_LENGTH_INVALID)
      for (var i = 0; i < publicKeys.length; ++i) {
        assert.isBuffer(publicKeys[i], messages.EC_PUBLIC_KEY_TYPE_INVALID)
        assert.isBufferLength2(publicKeys[i], 33, 65, messages.EC_PUBLIC_KEY_LENGTH_INVALID)
      }

      compressed = initCompressedValue(compressed, true)

      return secp256k1.publicKeyCombine(publicKeys, compressed)
    },

    /**
     * @param {Buffer} signature
     * @return {Buffer}
     */
    signatureNormalize: function (signature) {
      assert.isBuffer(signature, messages.ECDSA_SIGNATURE_TYPE_INVALID)
      assert.isBufferLength(signature, 64, messages.ECDSA_SIGNATURE_LENGTH_INVALID)

      return secp256k1.signatureNormalize(signature)
    },

    /**
     * @param {Buffer} signature
     * @return {Buffer}
     */
    signatureExport: function (signature) {
      assert.isBuffer(signature, messages.ECDSA_SIGNATURE_TYPE_INVALID)
      assert.isBufferLength(signature, 64, messages.ECDSA_SIGNATURE_LENGTH_INVALID)

      var sigObj = secp256k1.signatureExport(signature)
      var r = Buffer.concat([new Buffer([0]), sigObj.r])
      var s = Buffer.concat([new Buffer([0]), sigObj.s])

      var lenR = 33
      var posR = 0
      while (lenR > 1 && r[posR] === 0x00 && r[posR + 1] < 0x80) {
        --lenR
        ++posR
      }

      var lenS = 33
      var posS = 0
      while (lenS > 1 && s[posS] === 0x00 && s[posS + 1] < 0x80) {
        --lenS
        ++posS
      }

      var result = new Buffer(lenR + lenS + 6)
      result[0] = 0x30
      result[1] = 4 + lenR + lenS
      result[2] = 0x02
      result[3] = lenR
      r.copy(result, 4, posR)
      result[lenR + 4] = 0x02
      result[lenR + 5] = lenS
      s.copy(result, lenR + 6, posS)

      return result
    },

    /**
     * @param {Buffer} signature
     * @return {Buffer}
     */
    signatureImport: function (signature) {
      assert.isBuffer(signature, messages.ECDSA_SIGNATURE_TYPE_INVALID)
      assert.isLengthGTZero(signature, messages.ECDSA_SIGNATURE_LENGTH_INVALID)

      do {
        var o = {sig: signature, idx: 0}
        if ((o.sig.length < o.idx || o.sig[o.idx] !== 0x30) ||
            (o.sig.length < o.idx + 1 || o.sig[o.idx + 1] > 0x80) ||
            o.idx + o.sig[o.idx + 1] + 2 !== o.sig.length) {
          break
        }
        o.idx += 2

        var r = parseScalar(o)
        if (r === null) {
          break
        }

        var s = parseScalar(o)
        if (s === null) {
          break
        }

        return secp256k1.signatureImport({r: r, s: s})
      } while (false)

      throw new Error(messages.ECDSA_SIGNATURE_PARSE_DER_FAIL)
    },

    /**
     * @callback sign~noncefn
     * @param {Buffer} message
     * @param {Buffer} privateKey
     * @param {?Buffer} algo
     * @param {?Buffer} data
     * @param {number} attempt
     * @return {Buffer}
     */

    /**
     * @typedef {Object} sign~options
     * @param {Buffer} [data]
     * @param {sign~noncefn} [noncefn=nonce_function_rfc6979]
     */

    /**
     * @param {Buffer} message
     * @param {Buffer} privateKey
     * @param {sign~options} [options]
     * @return {{signature: Buffer, recovery: number}}
     */
    sign: function (message, privateKey, options) {
      assert.isBuffer(message, messages.MSG32_TYPE_INVALID)
      assert.isBufferLength(message, 32, messages.MSG32_LENGTH_INVALID)

      assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID)
      assert.isBufferLength(privateKey, 32, messages.EC_PRIVATE_KEY_LENGTH_INVALID)

      var data = null
      var noncefn = null
      if (options !== undefined) {
        assert.isObject(options, messages.OPTIONS_TYPE_INVALID)

        if (options.data !== undefined) {
          assert.isBuffer(options.data, messages.OPTIONS_DATA_TYPE_INVALID)
          assert.isBufferLength(options.data, 32, messages.OPTIONS_DATA_LENGTH_INVALID)
          data = options.data
        }

        if (options.noncefn !== undefined) {
          assert.isFunction(options.noncefn, messages.OPTIONS_NONCEFN_TYPE_INVALID)
          noncefn = options.noncefn
        }
      }

      return secp256k1.sign(message, privateKey, noncefn, data)
    },

    /**
     * @param {Buffer} message
     * @param {Buffer} signature
     * @param {Buffer} publicKey
     * @return {boolean}
     */
    verify: function (message, signature, publicKey) {
      assert.isBuffer(message, messages.MSG32_TYPE_INVALID)
      assert.isBufferLength(message, 32, messages.MSG32_LENGTH_INVALID)

      assert.isBuffer(signature, messages.ECDSA_SIGNATURE_TYPE_INVALID)
      assert.isBufferLength(signature, 64, messages.ECDSA_SIGNATURE_LENGTH_INVALID)

      assert.isBuffer(publicKey, messages.EC_PUBLIC_KEY_TYPE_INVALID)
      assert.isBufferLength2(publicKey, 33, 65, messages.EC_PUBLIC_KEY_LENGTH_INVALID)

      return secp256k1.verify(message, signature, publicKey)
    },

    /**
     * @param {Buffer} message
     * @param {Buffer} signature
     * @param {number} recovery
     * @param {boolean} [compressed=true]
     * @return {Buffer}
     */
    recover: function (message, signature, recovery, compressed) {
      assert.isBuffer(message, messages.MSG32_TYPE_INVALID)
      assert.isBufferLength(message, 32, messages.MSG32_LENGTH_INVALID)

      assert.isBuffer(signature, messages.ECDSA_SIGNATURE_TYPE_INVALID)
      assert.isBufferLength(signature, 64, messages.ECDSA_SIGNATURE_LENGTH_INVALID)

      assert.isNumber(recovery, messages.RECOVERY_ID_TYPE_INVALID)
      assert.isNumberInInterval(recovery, -1, 4, messages.RECOVERY_ID_VALUE_INVALID)

      compressed = initCompressedValue(compressed, true)

      return secp256k1.recover(message, signature, recovery, compressed)
    },

    /**
     * @param {Buffer} publicKey
     * @param {Buffer} privateKey
     * @param {?} options
     * @return {Buffer}
     */
    ecdh: function (publicKey, privateKey, options) {
      assert.isBuffer(publicKey, messages.EC_PUBLIC_KEY_TYPE_INVALID)
      assert.isBufferLength2(publicKey, 33, 65, messages.EC_PUBLIC_KEY_LENGTH_INVALID)

      assert.isBuffer(privateKey, messages.EC_PRIVATE_KEY_TYPE_INVALID)
      assert.isBufferLength(privateKey, 32, messages.EC_PRIVATE_KEY_LENGTH_INVALID)

      if (options !== undefined) {
        assert.isObject(options, messages.OPTIONS_TYPE_INVALID)
      }
    }
  }
}
