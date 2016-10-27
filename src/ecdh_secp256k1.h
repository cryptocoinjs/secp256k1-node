#ifndef _SECP256K1_NODE_ECDH_SECP256k1_
#define _SECP256K1_NODE_ECDH_SECP256k1_

int secp256k1_ecdh_sha256(const secp256k1_context*, unsigned char*, const secp256k1_pubkey*, const unsigned char*);
int secp256k1_ecdh_unsafe(const secp256k1_context*, secp256k1_pubkey*, const secp256k1_pubkey*, const unsigned char*);

#endif
