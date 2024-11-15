if (typeof BigInt !== 'undefined') {
  module.exports = require('./noble.js')
} else {
  module.exports = require('./elliptic.js')
}
