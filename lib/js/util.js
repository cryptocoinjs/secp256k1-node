'use strict'

/**
 * Represent num in a w-NAF form
 * @param {BN} num
 * @param {number} w
 * @return {number[]}
 */
exports.getNAF = function (num, w) {
  var naf = []
  var ws = 1 << w
  var ws2m1 = (ws << 1) - 1

  var k = num.clone()
  while (!k.isZero()) {
    var i = 0
    for (var d = 1; (k.words[0] & d) === 0 && i < 26; ++i, d <<= 1) {
      naf.push(0)
    }

    if (i !== 0) {
      k.iushrn(i)
    } else {
      var mod = k.words[0] & ws2m1
      if (mod >= ws) {
        naf.push(ws - mod)
        k.isubn(ws - mod).iushrn(1)
      } else {
        k.words[0] -= mod
        naf.push(mod)
        if (!k.isZero()) {
          for (i = w - 1; i > 0; --i) {
            naf.push(0)
          }

          k.iushrn(w)
        }
      }
    }
  }

  return naf
}
