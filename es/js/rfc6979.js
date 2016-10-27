import sha256hmac from './sha256-hmac'

const ZERO_BUFFER = Buffer.alloc(0)

export default function (message, privateKey, algo, data, count) {
  if (algo === null) algo = ZERO_BUFFER
  if (data === null) data = ZERO_BUFFER

  const key = Buffer.concat([privateKey, message, algo, data])

  // 3.2.b
  let v = Buffer.allocUnsafe(32).fill(0x01)

  // 3.2.c
  let k = Buffer.allocUnsafe(32).fill(0x00)

  // 3.2.d
  k = sha256hmac(k, Buffer.concat([v, Buffer.from([0x00]), key]))

  // 3.2.e
  v = sha256hmac(k, v)

  // 3.2.f
  k = sha256hmac(k, Buffer.concat([v, Buffer.from([0x01]), key]))

  // 3.2.g
  v = sha256hmac(k, v)

  // 3.2.h
  v = sha256hmac(k, v)
  for (let i = 0; i < count; ++i) {
    k = sha256hmac(k, Buffer.concat([v, Buffer.from([0x00])]))
    v = sha256hmac(k, v)
  }

  return v
}
