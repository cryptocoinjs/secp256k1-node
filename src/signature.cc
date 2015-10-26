#include <node.h>
#include <nan.h>
#include <secp256k1.h>

#include "messages.h"
#include "util.h"


extern secp256k1_context* secp256k1ctx;

NAN_METHOD(signatureNormalize) {
  Nan::HandleScope scope;

  secp256k1_ecdsa_signature sigin;
  if (signature_buffer_parse(info[0].As<v8::Object>(), &sigin) == 0) {
    return Nan::ThrowError(ECDSA_SIGNATURE_PARSE_FAIL);
  }

  secp256k1_ecdsa_signature sigout;
  if (secp256k1_ecdsa_signature_normalize(secp256k1ctx, &sigout, &sigin) == 0) {
    return Nan::ThrowError(ECDSA_SIGNATURE_NORMALIZE_FAIL);
  }

  unsigned char output[64];
  secp256k1_ecdsa_signature_serialize_compact(secp256k1ctx, &output[0], &sigout);

  info.GetReturnValue().Set(copyBuffer((const char*) &output[0], 64));
}

NAN_METHOD(signatureExport) {
  Nan::HandleScope scope;

  secp256k1_ecdsa_signature sig;
  if (signature_buffer_parse(info[0].As<v8::Object>(), &sig) == 0) {
    return Nan::ThrowError(ECDSA_SIGNATURE_PARSE_FAIL);
  }

  unsigned char output[300];
  size_t outputlen = 300;
  if (secp256k1_ecdsa_signature_serialize_der(secp256k1ctx, &output[0], &outputlen, &sig) == 0) {
    return Nan::ThrowError(ECDSA_SIGNATURE_SERIALIZE_DER_FAIL);
  }

  info.GetReturnValue().Set(copyBuffer((const char* ) &output[0], outputlen));
}

NAN_METHOD(signatureImport) {
  Nan::HandleScope scope;

  secp256k1_ecdsa_signature sig;
  v8::Local<v8::Object> sig_buffer = info[0].As<v8::Object>();
  const unsigned char* input = (unsigned char*) node::Buffer::Data(sig_buffer);
  size_t inputlen = node::Buffer::Length(sig_buffer);
  if (secp256k1_ecdsa_signature_parse_der(secp256k1ctx, &sig, &input[0], inputlen) == 0) {
    return Nan::ThrowError(ECDSA_SIGNATURE_PARSE_DER_FAIL);
  }

  unsigned char output[64];
  secp256k1_ecdsa_signature_serialize_compact(secp256k1ctx, &output[0], &sig);

  info.GetReturnValue().Set(copyBuffer((const char* ) &output[0], 64));
}
