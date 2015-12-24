'use strict'

function extend (target, source) {
  for (var key in source) {
    if (source.hasOwnProperty(key)) {
      target[key] = source[key]
    }
  }
}

require('./lib/ecparams').initG()

extend(exports, require('./lib/privatekey'))
extend(exports, require('./lib/publickey'))
extend(exports, require('./lib/signature'))
extend(exports, require('./lib/ecdsa'))
extend(exports, require('./lib/ecdh'))
