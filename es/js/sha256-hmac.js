import sha256 from './sha256'

export default function (key, data) {
  // block size in bytes (64 for sha256)
  const hkey = Buffer.allocUnsafe(64).fill(0)
  key.copy(hkey, 0)

  for (let i = 0; i < 64; ++i) hkey[i] = hkey[i] ^ 0x36
  data = sha256(Buffer.concat([hkey, data]))

  for (let j = 0; j < 64; ++j) hkey[j] = hkey[j] ^ 0x6a
  return sha256(Buffer.concat([hkey, data]))
}
