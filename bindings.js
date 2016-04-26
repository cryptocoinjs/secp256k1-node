'use strict'
try {
  module.exports = require('bindings')('secp256k1')
} catch (err) {
  module.exports = require('./elliptic')
}
