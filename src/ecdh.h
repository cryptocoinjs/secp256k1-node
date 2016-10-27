#ifndef _SECP256K1_NODE_ECDH_
# define _SECP256K1_NODE_ECDH_

#include <node.h>
#include <nan.h>

NAN_METHOD(ecdh_sha256);
NAN_METHOD(ecdh_unsafe);

#endif
