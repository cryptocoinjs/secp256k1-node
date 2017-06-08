#ifndef _SECP256K1_NODE_HASH_
# define _SECP256K1_NODE_HASH_

#include <node.h>
#include <nan.h>

NAN_METHOD(sha256);
NAN_METHOD(dsha256);

#endif
