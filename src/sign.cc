#include <node.h>
#include <nan.h>
#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include "messages.h"
#include "util.h"


extern secp256k1_context* secp256k1ctx;

class SignWorker : public Nan::AsyncWorker {
  public:
    SignWorker(v8::Local<v8::Object> msg32_buffer, v8::Local<v8::Object> seckey_buffer, Nan::Callback* callback)
      : Nan::AsyncWorker(callback), msg32_buffer(msg32_buffer), seckey_buffer(seckey_buffer) {}

    void Execute () {
      CHECK_ASYNC(msg32_buffer->IsUint8Array(), MSG32_TYPE_INVALID);
      CHECK_ASYNC(node::Buffer::Length(msg32_buffer) == 32, MSG32_LENGTH_INVALID);

      CHECK_ASYNC(seckey_buffer->IsUint8Array(), EC_PRIVKEY_TYPE_INVALID);
      CHECK_ASYNC(node::Buffer::Length(seckey_buffer) == 32, EC_PRIVKEY_LENGTH_INVALID);

      secp256k1_ecdsa_recoverable_signature sig;
      const unsigned char* msg32 = (const unsigned char*) node::Buffer::Data(msg32_buffer);
      const unsigned char* seckey = (const unsigned char*) node::Buffer::Data(seckey_buffer);
      if (secp256k1_ecdsa_sign_recoverable(secp256k1ctx, &sig, msg32, seckey, NULL, NULL) == 0) {
        return SetErrorMessage(ECDSA_SIGN_FAIL);
      }

      secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1ctx, &output[0], &recid, &sig);
    }

    void HandleOKCallback () {
      Nan::HandleScope scope;

      v8::Local<v8::Object> obj = Nan::New<v8::Object>();
      obj->Set(Nan::New<v8::String>("signature").ToLocalChecked(), Nan::CopyBuffer((const char*) &output[0], 64).ToLocalChecked());
      obj->Set(Nan::New<v8::String>("recovery").ToLocalChecked(), Nan::New<v8::Number>(recid));

      v8::Local<v8::Value> argv[] = {Nan::Null(), obj};

      callback->Call(2, argv);
    }

  protected:
    v8::Local<v8::Object> msg32_buffer;
    v8::Local<v8::Object> seckey_buffer;
    unsigned char output[64];
    int recid;
};

NAN_METHOD(sign) {
  Nan::HandleScope scope;

  v8::Local<v8::Function> callback = info[2].As<v8::Function>();
  CHECK(callback->IsFunction(), CALLBACK_TYPE_INVALID);

  SignWorker* worker = new SignWorker(
    info[0].As<v8::Object>(),
    info[1].As<v8::Object>(),
    new Nan::Callback(callback));

  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(signSync) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> msg32_buffer = info[0].As<v8::Object>();
  CHECK(msg32_buffer->IsUint8Array(), MSG32_TYPE_INVALID);
  CHECK(node::Buffer::Length(msg32_buffer) == 32, MSG32_LENGTH_INVALID);

  v8::Local<v8::Object> seckey_buffer = info[1].As<v8::Object>();
  CHECK(seckey_buffer->IsUint8Array(), EC_PRIVKEY_TYPE_INVALID);
  CHECK(node::Buffer::Length(seckey_buffer) == 32, EC_PRIVKEY_LENGTH_INVALID);

  secp256k1_ecdsa_recoverable_signature sig;
  const unsigned char* msg32 = (const unsigned char*) node::Buffer::Data(msg32_buffer);
  const unsigned char* seckey = (const unsigned char*) node::Buffer::Data(seckey_buffer);
  if (secp256k1_ecdsa_sign_recoverable(secp256k1ctx, &sig, msg32, seckey, NULL, NULL) == 0) {
    return Nan::ThrowError(ECDSA_SIGN_FAIL);
  }

  unsigned char output[64];
  int recid;
  secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1ctx, &output[0], &recid, &sig);

  v8::Local<v8::Object> obj = Nan::New<v8::Object>();
  obj->Set(Nan::New<v8::String>("signature").ToLocalChecked(), Nan::CopyBuffer((const char*) &output[0], 64).ToLocalChecked());
  obj->Set(Nan::New<v8::String>("recovery").ToLocalChecked(), Nan::New<v8::Number>(recid));
  info.GetReturnValue().Set(obj);
}
