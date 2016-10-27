#ifndef _SECP256K1_NODE_PUBLICKEY_
# define _SECP256K1_NODE_PUBLICKEY_

#include <node.h>
#include <nan.h>

NAN_METHOD(public_key_create);
NAN_METHOD(public_key_convert);
NAN_METHOD(public_key_verify);
NAN_METHOD(public_key_tweak_add);
NAN_METHOD(public_key_tweak_mul);
NAN_METHOD(public_key_combine);

#endif
