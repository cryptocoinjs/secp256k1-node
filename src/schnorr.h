#ifndef _SECP256K1_NODE_SCHNORR_
# define _SECP256K1_NODE_SCHNORR_

#include <node.h>
#include <nan.h>

NAN_METHOD(schnorr_sign);
NAN_METHOD(schnorr_verify);
NAN_METHOD(schnorr_recover);
NAN_METHOD(schnorr_generate_nonce_pair);
NAN_METHOD(schnorr_partial_sign);
NAN_METHOD(schnorr_partial_combine);

#endif
