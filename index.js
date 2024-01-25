try {
  module.exports = require('./bindings')
} catch (err) {
  try {
    module.exports = require('./bitcoinerlab')
  } catch (e) {
    module.exports = require('./elliptic')
  }
}
