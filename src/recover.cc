#include <node.h>
#include <nan.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include "messages.h"
#include "util.h"


extern secp256k1_context* secp256k1ctx;

class RecoverWorker : public Nan::AsyncWorker {
  public:
    RecoverWorker(v8::Local<v8::Object> msg32_buffer, v8::Local<v8::Object> sig_buffer, v8::Local<v8::Object> recid, Nan::Callback* callback)
      : Nan::AsyncWorker(callback), msg32_buffer(msg32_buffer), sig_buffer(sig_buffer), recid(recid) {}

    void Execute () {
      CHECK_ASYNC(node::Buffer::HasInstance(msg32_buffer), MSG32_TYPE_INVALID);
      CHECK_ASYNC(node::Buffer::Length(msg32_buffer) == 32, MSG32_LENGTH_INVALID);

      CHECK_ASYNC(node::Buffer::HasInstance(sig_buffer), ECDSA_SIGNATURE_TYPE_INVALID);
      CHECK_ASYNC(node::Buffer::Length(sig_buffer) == 64, ECDSA_SIGNATURE_LENGTH_INVALID);

      CHECK_ASYNC(sig_buffer->IsNumber(), ECDSA_SIGNATURE_RECOVERY_ID_TYPE_INVALID);

      secp256k1_ecdsa_recoverable_signature sig;
      const unsigned char* input = (unsigned char*) node::Buffer::Data(sig_buffer);
      if (secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1ctx, &sig, input, recid->Int32Value()) == 0) {
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
        Nan::CopyBuffer((const char*) &output[0], 33).ToLocalChecked()
      };

      callback->Call(2, argv);
    }

  protected:
    v8::Local<v8::Object> msg32_buffer;
    v8::Local<v8::Object> sig_buffer;
    v8::Local<v8::Object> recid;
    unsigned char output[33];
};

NAN_METHOD(recover) {
  Nan::HandleScope scope;

  v8::Local<v8::Function> callback = info[2].As<v8::Function>();
  CHECK(callback->IsFunction(), CALLBACK_TYPE_INVALID);

  RecoverWorker* worker = new RecoverWorker(
    info[0].As<v8::Object>(),
    info[1].As<v8::Object>(),
    info[2].As<v8::Object>(),
    new Nan::Callback(callback));

  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(recoverSync) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> msg32_buffer = info[0].As<v8::Object>();
  CHECK(node::Buffer::HasInstance(msg32_buffer), MSG32_TYPE_INVALID);
  CHECK(node::Buffer::Length(msg32_buffer) == 32, MSG32_LENGTH_INVALID);

  v8::Local<v8::Object> sig_buffer = info[1].As<v8::Object>();
  CHECK(node::Buffer::HasInstance(sig_buffer), ECDSA_SIGNATURE_TYPE_INVALID);
  CHECK(node::Buffer::Length(sig_buffer) == 64, ECDSA_SIGNATURE_LENGTH_INVALID);

  v8::Local<v8::Object> recid = info[2].As<v8::Object>();
  CHECK(sig_buffer->IsNumber(), ECDSA_SIGNATURE_RECOVERY_ID_TYPE_INVALID);

  secp256k1_ecdsa_recoverable_signature sig;
  const unsigned char* input = (unsigned char*) node::Buffer::Data(sig_buffer);
  if (secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1ctx, &sig, input, recid->Int32Value()) == 0) {
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
  info.GetReturnValue().Set(Nan::CopyBuffer((const char*) &output[0], 33).ToLocalChecked());
}
