'use strict'

function extend (target, source) {
  for (var key in source) {
    if (source.hasOwnProperty(key)) {
      target[key] = source[key]
    }
  }
}

exports.ecparams = require('./lib/ecparams')
exports.ECPoint = require('./lib/ecpoint')
exports.ECJPoint = require('./lib/ecjpoint')

extend(exports, require('./lib/privatekey'))
extend(exports, require('./lib/publickey'))
extend(exports, require('./lib/signature'))
extend(exports, require('./lib/ecdsa'))
extend(exports, require('./lib/ecdh'))
