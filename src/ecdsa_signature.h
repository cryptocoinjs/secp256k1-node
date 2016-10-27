#ifndef _SECP256K1_NODE_ECDSA_SIGNATURE_
# define _SECP256K1_NODE_ECDSA_SIGNATURE_

#include <node.h>
#include <nan.h>

NAN_METHOD(ecdsa_signature_normalize);
NAN_METHOD(ecdsa_signature_export);
NAN_METHOD(ecdsa_signature_import);
NAN_METHOD(ecdsa_signature_import_lax);

#endif
