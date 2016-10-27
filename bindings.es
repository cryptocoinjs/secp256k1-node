import bindings from 'bindings'

const secp256k1 = bindings('secp256k1')
export const privateKey = secp256k1.privateKey
export const publicKey = secp256k1.publicKey
export const ecdsa = secp256k1.ecdsa
export const schnorr = secp256k1.schnorr
export const ecdh = secp256k1.ecdh
