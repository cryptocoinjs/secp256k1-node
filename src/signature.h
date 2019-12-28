#ifndef _SECP256K1_NODE_SIGNATURE_
#define _SECP256K1_NODE_SIGNATURE_

#include <nan.h>
#include <node.h>

NAN_METHOD(signatureNormalize);
NAN_METHOD(signatureExport);
NAN_METHOD(signatureImport);
NAN_METHOD(signatureImportLax);

#endif
