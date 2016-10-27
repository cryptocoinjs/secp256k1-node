const K = [
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

const BLOCK_SIZE = 512
const DELTA8 = BLOCK_SIZE / 8
const DELTA32 = BLOCK_SIZE / 32
const PAD_LENGTH = 64 / 8

export default function (data) {
  const state = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
  ]

  let msg = Array.from(data)

  // pad
  let extra = DELTA8 - ((msg.length + PAD_LENGTH) % DELTA8)
  const pad = new Array(extra + PAD_LENGTH).fill(0)
  pad[0] = 0x80

  pad[extra++] = pad[extra++] = pad[extra++] = pad[extra++] = 0
  // len is msg.length << 3
  pad[extra++] = (msg.length >>> 21) & 0xff
  pad[extra++] = (msg.length >>> 13) & 0xff
  pad[extra++] = (msg.length >>> 5) & 0xff
  pad[extra++] = (msg.length << 3) & 0xff
  msg = msg.concat(pad)

  // update
  const cmsg = new Array(msg.length / 4)
  for (let i = 0, j = 0; i < cmsg.length; i++, j += 4) {
    cmsg[i] = (msg[j] << 24) | (msg[j + 1] << 16) | (msg[j + 2] << 8) | msg[j + 3]
  }

  const W = new Array(64)
  for (let start = 0; start < cmsg.length; start += DELTA32) {
    for (let i = 0; i < 16; ++i) W[i] = cmsg[start + i]
    for (let i = 16; i < 64; ++i) W[i] = (gamma1(W[i - 2]) + W[i - 7] + gamma0(W[i - 15]) + W[i - 16]) | 0

    let a = state[0]
    let b = state[1]
    let c = state[2]
    let d = state[3]
    let e = state[4]
    let f = state[5]
    let g = state[6]
    let h = state[7]

    for (let i = 0; i < W.length; ++i) {
      const T1 = (h + sigma1(e) + ch(e, f, g) + K[i] + W[i]) | 0
      const T2 = (sigma0(a) + maj(a, b, c)) | 0
      h = g
      g = f
      f = e
      e = (d + T1) | 0
      d = c
      c = b
      b = a
      a = (T1 + T2) | 0
    }

    state[0] = (state[0] + a) | 0
    state[1] = (state[1] + b) | 0
    state[2] = (state[2] + c) | 0
    state[3] = (state[3] + d) | 0
    state[4] = (state[4] + e) | 0
    state[5] = (state[5] + f) | 0
    state[6] = (state[6] + g) | 0
    state[7] = (state[7] + h) | 0
  }

  // digest
  const digest = Buffer.allocUnsafe(32)
  for (let i = 0, j = 0; i < state.length; ++i, j += 4) {
    const v = state[i]
    digest[j] = v >>> 24
    digest[j + 1] = (v >>> 16) & 0xff
    digest[j + 2] = (v >>> 8) & 0xff
    digest[j + 3] = v & 0xff
  }

  return digest
}

function ch (x, y, z) {
  return z ^ (x & (y ^ z))
}

function maj (x, y, z) {
  return (x & y) | (z & (x | y))
}

function sigma0 (x) {
  return (x >>> 2 | x << 30) ^ (x >>> 13 | x << 19) ^ (x >>> 22 | x << 10)
}

function sigma1 (x) {
  return (x >>> 6 | x << 26) ^ (x >>> 11 | x << 21) ^ (x >>> 25 | x << 7)
}

function gamma0 (x) {
  return (x >>> 7 | x << 25) ^ (x >>> 18 | x << 14) ^ (x >>> 3)
}

function gamma1 (x) {
  return (x >>> 17 | x << 15) ^ (x >>> 19 | x << 13) ^ (x >>> 10)
}
