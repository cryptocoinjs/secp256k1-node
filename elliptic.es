import * as secp256k1 from './es/elliptic'
import * as api from './es/api'

export const privateKey = api.privateKey(secp256k1.privateKey)
export const publicKey = api.publicKey(secp256k1.publicKey)
export const ecdsa = api.ecdsa(secp256k1.ecdsa)
export const schnorr = api.schnorr(secp256k1.schnorr)
export const ecdh = api.ecdh(secp256k1.ecdh)
