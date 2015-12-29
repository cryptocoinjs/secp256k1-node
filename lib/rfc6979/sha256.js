'use strict'

var K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

var H = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

var BLOCK_SIZE = 512
var DELTA8 = BLOCK_SIZE / 8
var DELTA32 = BLOCK_SIZE / 32
var PAD_LENGTH = 64 / 8

/**
 * @param {Buffer} data
 * @return {Buffer}
 */
module.exports = function sha256 (data) {
  var i
  var j

  var hs = H.slice()

  var msg = new Array(data.length)
  for (i = 0; i < data.length; ++i) {
    msg[i] = data[i]
  }

  // pad
  var extra = DELTA8 - ((msg.length + PAD_LENGTH) % DELTA8)
  var pad = new Array(extra + PAD_LENGTH)
  pad[0] = 0x80
  for (i = 1; i < extra; i++) {
    pad[i] = 0
  }

  pad[i++] = pad[i++] = pad[i++] = pad[i++] = 0
  // len is msg.length << 3
  pad[i++] = (msg.length >>> 21) & 0xff
  pad[i++] = (msg.length >>> 13) & 0xff
  pad[i++] = (msg.length >>> 5) & 0xff
  pad[i++] = (msg.length << 3) & 0xff
  msg = msg.concat(pad)

  // update
  var cmsg = new Array(msg.length / 4)
  for (i = 0, j = 0; i < cmsg.length; i++, j += 4) {
    cmsg[i] = ((msg[j] << 24) | (msg[j + 1] << 16) | (msg[j + 2] << 8) | msg[j + 3]) >>> 0
  }

  var W = new Array(64)
  for (var start = 0; start < cmsg.length; start += DELTA32) {
    for (i = 0; i < 16; ++i) {
      W[i] = cmsg[start + i]
    }
    for (; i < W.length; ++i) {
      W[i] = sum32_4(g1_256(W[i - 2]), W[i - 7], g0_256(W[i - 15]), W[i - 16])
    }

    var a = hs[0]
    var b = hs[1]
    var c = hs[2]
    var d = hs[3]
    var e = hs[4]
    var f = hs[5]
    var g = hs[6]
    var h = hs[7]

    for (i = 0; i < W.length; ++i) {
      var T1 = sum32_5(h, s1_256(e), ch32(e, f, g), K[i], W[i])
      var T2 = sum32(s0_256(a), maj32(a, b, c))
      h = g
      g = f
      f = e
      e = sum32(d, T1)
      d = c
      c = b
      b = a
      a = sum32(T1, T2)
    }

    hs[0] = sum32(hs[0], a)
    hs[1] = sum32(hs[1], b)
    hs[2] = sum32(hs[2], c)
    hs[3] = sum32(hs[3], d)
    hs[4] = sum32(hs[4], e)
    hs[5] = sum32(hs[5], f)
    hs[6] = sum32(hs[6], g)
    hs[7] = sum32(hs[7], h)
  }

  // digest
  var dgst = new Buffer(hs.length * 4)
  for (i = 0, j = 0; i < hs.length; ++i, j += 4) {
    var m = hs[i]
    dgst[j] = m >>> 24
    dgst[j + 1] = (m >>> 16) & 0xff
    dgst[j + 2] = (m >>> 8) & 0xff
    dgst[j + 3] = m & 0xff
  }

  return dgst
}

function rotr32 (w, b) {
  return (w >>> b) | (w << (32 - b))
}

function sum32 (a, b) {
  return (a + b) >>> 0
}

function sum32_4 (a, b, c, d) {
  return (a + b + c + d) >>> 0
}

function sum32_5 (a, b, c, d, e) {
  return (a + b + c + d + e) >>> 0
}

function ch32 (x, y, z) {
  return (x & y) ^ ((~x) & z)
}

function maj32 (x, y, z) {
  return (x & y) ^ (x & z) ^ (y & z)
}

function s0_256 (x) {
  return rotr32(x, 2) ^ rotr32(x, 13) ^ rotr32(x, 22)
}

function s1_256 (x) {
  return rotr32(x, 6) ^ rotr32(x, 11) ^ rotr32(x, 25)
}

function g0_256 (x) {
  return rotr32(x, 7) ^ rotr32(x, 18) ^ (x >>> 3)
}

function g1_256 (x) {
  return rotr32(x, 17) ^ rotr32(x, 19) ^ (x >>> 10)
}
