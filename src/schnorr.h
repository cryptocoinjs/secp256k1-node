#ifndef _SECP256K1_NODE_SCHNORR_
# define _SECP256K1_NODE_SCHNORR_

#include <node.h>
#include <nan.h>

NAN_METHOD(schnorrSign);
NAN_METHOD(schnorrVerify);
NAN_METHOD(schnorrRecover);
NAN_METHOD(schnorrGenerateNoncePair);
NAN_METHOD(schnorrPartialSign);
NAN_METHOD(schnorrPartialCombine);

#endif
