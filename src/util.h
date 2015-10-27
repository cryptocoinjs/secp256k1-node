#ifndef _SECP256K1_NODE_UTIL_
# define _SECP256K1_NODE_UTIL_

#include <node.h>
#include <nan.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>


extern secp256k1_context* secp256k1ctx;

inline v8::Local<v8::Object> copyBuffer(const char* data, size_t datalen) {
  return Nan::CopyBuffer(data, datalen).ToLocalChecked();
}

inline int pubkey_buffer_parse(v8::Local<v8::Object> pubkey_buffer, secp256k1_pubkey* pubkey) {
  const unsigned char* input = (unsigned char*) node::Buffer::Data(pubkey_buffer);
  size_t inputlen = node::Buffer::Length(pubkey_buffer);
  return secp256k1_ec_pubkey_parse(secp256k1ctx, pubkey, input, inputlen);
}

inline int signature_buffer_parse(v8::Local<v8::Object> sig_buffer, secp256k1_ecdsa_signature* sig) {
  if (node::Buffer::Length(sig_buffer) != 64) {
    return 0;
  }

  const unsigned char* input = (unsigned char*) node::Buffer::Data(sig_buffer);
  return secp256k1_ecdsa_signature_parse_compact(secp256k1ctx, sig, input);
}

inline int recoverable_signature_buffer_parse(v8::Local<v8::Object> sig_buffer, int recid, secp256k1_ecdsa_recoverable_signature* sig) {
  if (node::Buffer::Length(sig_buffer) != 64) {
    return 0;
  }

  const unsigned char* input = (unsigned char*) node::Buffer::Data(sig_buffer);
  return secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1ctx, sig, input, recid);
}

#endif
