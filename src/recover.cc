#include <node.h>
#include <nan.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include "messages.h"
#include "util.h"


extern secp256k1_context* secp256k1ctx;

class RecoverWorker : public Nan::AsyncWorker {
  public:
    RecoverWorker(const unsigned char* msg32, v8::Local<v8::Object> sig_buffer, int recid, Nan::Callback* callback)
      : Nan::AsyncWorker(callback), msg32(msg32), sig_buffer(sig_buffer), recid(recid) {}

    void Execute () {
      secp256k1_ecdsa_recoverable_signature sig;
      if (recoverable_signature_buffer_parse(sig_buffer, recid, &sig) == 0) {
        return SetErrorMessage(ECDSA_SIGNATURE_PARSE_FAIL);
      }

      secp256k1_pubkey pubkey;
      if (secp256k1_ecdsa_recover(secp256k1ctx, &pubkey, &sig, &msg32[0]) == 0) {
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
    const unsigned char* msg32;
    v8::Local<v8::Object> sig_buffer;
    int recid;
    unsigned char output[33];
};

NAN_METHOD(recover) {
  Nan::HandleScope scope;

  const unsigned char* msg32 = (const unsigned char*) node::Buffer::Data(info[0]);
  v8::Local<v8::Object> sig_buffer = info[1].As<v8::Object>();
  int recid = info[2]->IntegerValue();
  Nan::Callback* callback = new Nan::Callback(info[3].As<v8::Function>());

  RecoverWorker* worker = new RecoverWorker(&msg32[0], sig_buffer, recid, callback);
  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(recoverSync) {
  Nan::HandleScope scope;

  secp256k1_ecdsa_recoverable_signature sig;
  if (recoverable_signature_buffer_parse(info[1].As<v8::Object>(), info[2]->IntegerValue(), &sig) == 0) {
    return Nan::ThrowError(ECDSA_SIGNATURE_PARSE_FAIL);
  }

  secp256k1_pubkey pubkey;
  const unsigned char* msg32 = (const unsigned char*) node::Buffer::Data(info[0]);
  if (secp256k1_ecdsa_recover(secp256k1ctx, &pubkey, &sig, &msg32[0]) == 0) {
    return Nan::ThrowError(ECDSA_RECOVER_FAIL);
  }

  unsigned char output[33];
  size_t outputlen;
  secp256k1_ec_pubkey_serialize(secp256k1ctx, &output[0], &outputlen, &pubkey, SECP256K1_EC_COMPRESSED);
  info.GetReturnValue().Set(copyBuffer((const char* ) &output[0], 33));
}
