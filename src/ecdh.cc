#include <node.h>
#include <nan.h>
#include <secp256k1.h>
#include <secp256k1_ecdh.h>

#include "messages.h"
#include "util.h"


extern secp256k1_context* secp256k1ctx;

class ECDHWorker : public Nan::AsyncWorker {
  public:
    ECDHWorker(v8::Local<v8::Object> pubkey_buffer, v8::Local<v8::Object> seckey_buffer, Nan::Callback* callback)
      : Nan::AsyncWorker(callback), pubkey_buffer(pubkey_buffer), seckey_buffer(seckey_buffer) {}

    void Execute () {
      CHECK_ASYNC(node::Buffer::HasInstance(pubkey_buffer), EC_PUBKEY_TYPE_INVALID);
      CHECK_ASYNC(node::Buffer::Length(pubkey_buffer) == 33 || node::Buffer::Length(pubkey_buffer) == 65, EC_PUBKEY_LENGTH_INVALID);

      secp256k1_pubkey pubkey;
      const unsigned char* pubkey_input = (unsigned char*) node::Buffer::Data(pubkey_buffer);
      size_t pubkey_inputlen = node::Buffer::Length(pubkey_buffer);
      if (secp256k1_ec_pubkey_parse(secp256k1ctx, &pubkey, pubkey_input, pubkey_inputlen) == 0) {
        return SetErrorMessage(EC_PUBKEY_PARSE_FAIL);
      }

      CHECK_ASYNC(node::Buffer::HasInstance(seckey_buffer), EC_PRIVKEY_TYPE_INVALID);
      CHECK_ASYNC(node::Buffer::Length(seckey_buffer) == 32, EC_PRIVKEY_LENGTH_INVALID);

      const unsigned char* seckey = (const unsigned char*) node::Buffer::Data(seckey_buffer);
      if (secp256k1_ecdh(secp256k1ctx, &output[0], &pubkey, seckey) == 0) {
        return SetErrorMessage(ECDH_FAIL);
      }
    }

    void HandleOKCallback () {
      Nan::HandleScope scope;

      v8::Local<v8::Value> argv[] = {
        Nan::Null(),
        Nan::CopyBuffer((const char*) &output[0], 32).ToLocalChecked()
      };

      callback->Call(2, argv);
    }

  protected:
    v8::Local<v8::Object> pubkey_buffer;
    v8::Local<v8::Object> seckey_buffer;
    unsigned char output[32];
};

NAN_METHOD(ecdh) {
  Nan::HandleScope scope;

  v8::Local<v8::Function> callback = info[2].As<v8::Function>();
  CHECK(callback->IsFunction(), CALLBACK_TYPE_INVALID);

  ECDHWorker* worker = new ECDHWorker(
    info[0].As<v8::Object>(),
    info[1].As<v8::Object>(),
    new Nan::Callback(callback));

  Nan::AsyncQueueWorker(worker);
}

NAN_METHOD(ecdhSync) {
  Nan::HandleScope scope;

  v8::Local<v8::Object> pubkey_buffer = info[0].As<v8::Object>();
  CHECK(node::Buffer::HasInstance(pubkey_buffer), EC_PUBKEY_TYPE_INVALID);
  CHECK(node::Buffer::Length(pubkey_buffer) == 33 || node::Buffer::Length(pubkey_buffer) == 65, EC_PUBKEY_LENGTH_INVALID);

  secp256k1_pubkey pubkey;
  const unsigned char* pubkey_input = (unsigned char*) node::Buffer::Data(pubkey_buffer);
  size_t pubkey_inputlen = node::Buffer::Length(pubkey_buffer);
  if (secp256k1_ec_pubkey_parse(secp256k1ctx, &pubkey, pubkey_input, pubkey_inputlen) == 0) {
    return Nan::ThrowError(EC_PUBKEY_PARSE_FAIL);
  }

  v8::Local<v8::Object> seckey_buffer = info[1].As<v8::Object>();
  CHECK(node::Buffer::HasInstance(seckey_buffer), EC_PRIVKEY_TYPE_INVALID);
  CHECK(node::Buffer::Length(seckey_buffer) == 32, EC_PRIVKEY_LENGTH_INVALID);

  unsigned char output[32];
  const unsigned char* seckey = (const unsigned char*) node::Buffer::Data(seckey_buffer);
  if (secp256k1_ecdh(secp256k1ctx, &output[0], &pubkey, seckey) == 0) {
    return Nan::ThrowError(ECDH_FAIL);
  }

  info.GetReturnValue().Set(Nan::CopyBuffer((const char*) &output[0], 32).ToLocalChecked());
}
