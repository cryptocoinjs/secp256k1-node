#ifndef _SECP256K1_NODE_ECDSA_
# define _SECP256K1_NODE_ECDSA_

#include <node.h>
#include <nan.h>

NAN_METHOD(ecdsa_sign);
NAN_METHOD(ecdsa_verify);
NAN_METHOD(ecdsa_recover);

#endif
