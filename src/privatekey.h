#ifndef _SECP256K1_NODE_PRIVATEKEY_
# define _SECP256K1_NODE_PRIVATEKEY_

#include <node.h>
#include <nan.h>

NAN_METHOD(private_key_verify);
NAN_METHOD(private_key_export);
NAN_METHOD(private_key_import);
NAN_METHOD(private_key_tweak_add);
NAN_METHOD(private_key_tweak_mul);

#endif
