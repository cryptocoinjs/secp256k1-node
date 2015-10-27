#include <node.h>
#include <nan.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include "messages.h"
#include "util.h"


extern secp256k1_context* secp256k1ctx;

class RecoverWorker : public Nan::AsyncWorker {
  public:
    RecoverWorker(v8::Local<v8::Object> msg32_buffer, v8::Local<v8::Object> sig_buffer, int recid, Nan::Callback* callback)
      : Nan::AsyncWorker(callback), msg32_buffer(msg32_buffer), sig_buffer(sig_buffer), recid(recid) {}

    void Execute () {
      if (node::Buffer::Length(msg32_buffer) != 32) {
        return SetErrorMessage(MSG32_LENGTH_INVALID);
      }

      secp256k1_ecdsa_recoverable_signature sig;
      if (recoverable_signature_buffer_parse(sig_buffer, recid, &sig) == 0) {
        return SetErrorMessage(ECDSA_SIGNATURE_PARSE_FAIL);
      }

      secp256k1_pubkey pubkey;
      const unsigned char* msg32 = (const unsigned char*) node::Buffer::Data(msg32_buffer);
      if (secp256k1_ecdsa_recover(secp256k1ctx, &pubkey, &sig, msg32) == 0) {
        return SetErrorMessage(ECDSA_RECOVER_FAIL);
      }

      unsigned char output[33];
      size_t outputlen;
      secp256k1_ec_pubkey_serialize(secp256k1ctx, &output[0], &outputlen, &pubkey, SECP256K1_EC_COMPRESSED);
    }

    void HandleOKCallback () {
      Nan::HandleScope scope;

      v8::Local<v8::Value> argv[] = {
        Nan::Null(),
        copyBuffer((const char*) &output[0], 33)
      };

      callback->Call(2, argv);
    }

  protected:
    v8::Local<v8::Object> msg32_buffer;
    v8::Local<v8::Object> sig_buffer;
    int recid;
    unsigned char output[33];
};

NAN_METHOD(recover) {
  Nan::HandleScope scope;

  RecoverWorker* worker = new RecoverWorker(
    info[0].As<v8::Object>(),
    info[1].As<v8::Object>(),
    info[2]->IntegerValue(),
    new Nan::Callback(info[3].As<v8::Function>()));

  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(recoverSync) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> msg32_buffer = info[0].As<v8::Object>();
  if (node::Buffer::Length(msg32_buffer) != 32) {
    return Nan::ThrowError(MSG32_LENGTH_INVALID);
  }

  secp256k1_ecdsa_recoverable_signature sig;
  if (recoverable_signature_buffer_parse(info[1].As<v8::Object>(), info[2]->IntegerValue(), &sig) == 0) {
    return Nan::ThrowError(ECDSA_SIGNATURE_PARSE_FAIL);
  }

  secp256k1_pubkey pubkey;
  const unsigned char* msg32 = (const unsigned char*) node::Buffer::Data(msg32_buffer);
  if (secp256k1_ecdsa_recover(secp256k1ctx, &pubkey, &sig, msg32) == 0) {
    return Nan::ThrowError(ECDSA_RECOVER_FAIL);
  }

  unsigned char output[33];
  size_t outputlen;
  secp256k1_ec_pubkey_serialize(secp256k1ctx, &output[0], &outputlen, &pubkey, SECP256K1_EC_COMPRESSED);
  info.GetReturnValue().Set(copyBuffer((const char* ) &output[0], 33));
}
