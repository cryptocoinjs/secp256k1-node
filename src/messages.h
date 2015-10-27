#ifndef _SECP256K1_NODE_MESSAGES_
# define _SECP256K1_NODE_MESSAGES_

#define PRIVKEY_LENGTH_INVALID "seckey length is invalid"
#define MSG32_LENGTH_INVALID "message length is invalid"
#define TWEAK_LENGTH_INVALID "tweak length is invalid"

#define EC_PRIVKEY_TWEAK_ADD_FAIL "tweak out of range or resulting secret key is invalid"
#define EC_PRIVKEY_TWEAK_MUL_FAIL "tweak out of range"

#define EC_PUBKEY_PARSE_FAIL "the public key could not be parsed or is invalid"
#define EC_PUBKEY_CREATE_FAIL "secret was invalid, try again"
#define EC_PUBKEY_TWEAK_ADD_FAIL "tweak out of range or resulting public key is invalid"
#define EC_PUBKEY_TWEAK_MUL_FAIL "tweak out of range"
#define EC_PUBKEY_COMBINE_FAIL "the sum of the public keys is not valid"

#define ECDSA_SIGNATURE_PARSE_FAIL "couldn't parse signature"
#define ECDSA_SIGNATURE_PARSE_DER_FAIL "couldn't parse DER signature"
#define ECDSA_SIGNATURE_SERIALIZE_DER_FAIL "couldn't serialize signature to DER format"
#define ECDSA_SIGNATURE_NORMALIZE_FAIL "couldn't normalize signature"

#define ECDSA_SIGN_FAIL "nonce generation function failed or private key is invalid"
#define ECDSA_VERIFY_FAIL "incorrect or unparseable signature"
#define ECDSA_RECOVER_FAIL "couldn't recover public key from signature"

#define ECDH_FAIL "scalar was invalid (zero or overflow)"

#endif
