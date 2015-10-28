#ifndef _SECP256K1_NODE_UTIL_
# define _SECP256K1_NODE_UTIL_

#include <node.h>
#include <nan.h>


#define NEW_BUFFER(data, datalen) Nan::CopyBuffer((const char*) data, datalen).ToLocalChecked()

#define CHECK(value, msg) { if (!(value)) { return Nan::ThrowError(msg); } }
#define CHECK_ASYNC(value, msg) { if (!(value)) { return SetErrorMessage(msg); } }

#endif
