#ifndef _SECP256K1_NODE_MESSAGES_
# define _SECP256K1_NODE_MESSAGES_

#define COMPRESSED_TYPE_INVALID "compressed should be a boolean"

#define EC_PRIVATE_KEY_TYPE_INVALID "private key should be a Buffer"
#define EC_PRIVATE_KEY_LENGTH_INVALID "private key length is invalid"
#define EC_PRIVATE_KEY_TWEAK_ADD_FAIL "tweak out of range or resulting private key is invalid"
#define EC_PRIVATE_KEY_TWEAK_MUL_FAIL "tweak out of range"
#define EC_PRIVATE_KEY_EXPORT_DER_FAIL "couldn't export to DER format"
#define EC_PRIVATE_KEY_IMPORT_DER_FAIL "couldn't import from DER format"

#define EC_PUBLIC_KEYS_TYPE_INVALID "public keys should be an Array"
#define EC_PUBLIC_KEYS_LENGTH_INVALID "public keys Array should have at least 1 element"
#define EC_PUBLIC_KEY_TYPE_INVALID "public key should be a Buffer"
#define EC_PUBLIC_KEY_LENGTH_INVALID "public key length is invalid"
#define EC_PUBLIC_KEY_PARSE_FAIL "the public key could not be parsed or is invalid"
#define EC_PUBLIC_KEY_CREATE_FAIL "private was invalid, try again"
#define EC_PUBLIC_KEY_TWEAK_ADD_FAIL "tweak out of range or resulting public key is invalid"
#define EC_PUBLIC_KEY_TWEAK_MUL_FAIL "tweak out of range"
#define EC_PUBLIC_KEY_COMBINE_FAIL "the sum of the public keys is not valid"

#define ECDH_FAIL "scalar was invalid (zero or overflow)"

#define ECDSA_SIGNATURE_TYPE_INVALID "signature should be a Buffer"
#define ECDSA_SIGNATURE_LENGTH_INVALID "signature length is invalid"
#define ECDSA_SIGNATURE_PARSE_FAIL "couldn't parse signature"
#define ECDSA_SIGNATURE_PARSE_DER_FAIL "couldn't parse DER signature"
#define ECDSA_SIGNATURE_SERIALIZE_DER_FAIL "couldn't serialize signature to DER format"

#define ECDSA_RECOVERY_ID_TYPE_INVALID "recovery should be a Number"
#define ECDSA_RECOVERY_ID_VALUE_INVALID "recovery should have value in [0, 3]"

#define ECDSA_SIGN_FAIL "nonce generation function failed or private key is invalid"
#define ECDSA_RECOVER_FAIL "couldn't recover public key from signature"

#define SCHNORR_SIGNATURE_TYPE_INVALID "signature should be a Buffer"
#define SCHNORR_SIGNATURE_LENGTH_INVALID "signature length is invalid"
#define SCHNORR_SIGN_FAIL "nonce generation function failed or private key is invalid"
#define SCHNORR_RECOVER_FAIL "couldn't recover public key from signature"
#define SCHNORR_GENERATE_NONCE_PAIR_FAIL "nonce generation function failed"
#define SCHNORR_PARTIAL_SIGN_FAIL "invalid private key, nonce, public nonces, or no valid signature exists with this combination of keys"
#define SCHNORR_PARTIAL_COMBINE_FAIL "some inputs were invalid or the resulting signature is not valid"
#define SCHNORR_SIGNATURES_TYPE_INVALID "signatures should be an Array"
#define SCHNORR_SIGNATURES_LENGTH_INVALID "signatures Array should have at least 1 element"

#define MESSAGE_TYPE_INVALID "message should be a Buffer"
#define MESSAGE_LENGTH_INVALID "message length is invalid"

#define NONCE_FUNCTION_TYPE_INVALID "noncefn should be a Function"
#define NONCE_DATA_TYPE_INVALID "noncedata should be a Buffer"
#define NONCE_DATA_LENGTH_INVALID "noncedata length is invalid"

#define TWEAK_TYPE_INVALID "tweak should be a Buffer"
#define TWEAK_LENGTH_INVALID "tweak length is invalid"

#endif
