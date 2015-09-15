#ifndef ASYNC_H
#define ASYNC_H

#include <nan.h>
#include <node.h>
#include "./util.h"
using namespace v8;

//Create a async Signature
class SignWorker : public Nan::AsyncWorker {
 public:
  // Constructor
  SignWorker(Nan::Callback *callback, const unsigned char *msg32, const unsigned char *seckey, bool DER=false)
    : Nan::AsyncWorker(callback), msg32(msg32), seckey(seckey), DER(DER) {}
  // Destructor
  ~SignWorker() {}

  // Executed inside the worker-thread.
  // It is not safe to access V8, or V8 data structures
  // here, so everything we need for input and output
  // should go on `this`.
  void Execute () {
    result = secp256k1_ecdsa_sign(secp256k1ctx, msg32, &sig, seckey, NULL, NULL);
  }

  // Executed when the async work is complete
  // this function will be run inside the main event loop
  // so it is safe to use V8 again
  void HandleOKCallback () {
    Nan::HandleScope scope;

    char* output;
    int outputlen;
    int recid;

    serialize_sig(DER, output, &outputlen, &recid, &sig);
      
    Local<Value> argv[3] = {
      Nan::New<Number>(result),
      localBuffer(output, size_t(outputlen)),
      Nan::New<Number>(recid)
    };

    delete output;
    callback->Call(3, argv);
  }

 protected:
  const unsigned char * msg32;
  const unsigned char * seckey;
  int result; //1 if the nonce generation function failed, or the private key was invalid.
  secp256k1_ecdsa_signature_t sig;
  bool DER; //whether to return a DER sig
};

//recover's the public key from a signature
class RecoverWorker : public Nan::AsyncWorker {
 public:
  // Constructor
  RecoverWorker(Nan::Callback *callback, const unsigned char *msg32, secp256k1_ecdsa_signature_t *sig, int compressed=true)
    : Nan::AsyncWorker(callback), msg32(msg32), sig(sig), compressed(compressed) {}
  // Destructor
  ~RecoverWorker() {
    delete sig;
  }

  void Execute () {
    this->result = secp256k1_ecdsa_recover(secp256k1ctx, msg32, sig, &pubkey);
  }

  void HandleOKCallback () {
    Nan::HandleScope scope;

    unsigned char output[65];
    int outputlen;

    secp256k1_ec_pubkey_serialize(secp256k1ctx, output, &outputlen, &pubkey, compressed);

    Local<Value> argv[] = {
      Nan::New<Number>(result),
      localBuffer((char*)output, size_t(outputlen))
    };
    callback->Call(2, argv);
  }

 protected:
  const unsigned char * msg32;
  secp256k1_ecdsa_signature_t * sig;
  secp256k1_pubkey_t pubkey;
  bool compressed;
  int result;
};

class VerifyWorker : public Nan::AsyncWorker {
 public:
  // Constructor
  VerifyWorker(Nan::Callback *callback, const unsigned char *msg32, secp256k1_ecdsa_signature_t *sig, secp256k1_pubkey_t *pubkey)
    : Nan::AsyncWorker(callback), msg32(msg32), sig(sig), pubkey(pubkey) {}
  // Destructor
  ~VerifyWorker() {
    delete sig;
    delete pubkey;
  }

  void Execute () {
    result = secp256k1_ecdsa_verify(secp256k1ctx, msg32, sig, pubkey);
  }

  void HandleOKCallback () {
    Nan::HandleScope scope;
    Local<Value> argv[] = {
      Nan::New<Number>(result),
    };
    callback->Call(1, argv);
  }

 protected:
  int result;
  const unsigned char * msg32;
  secp256k1_ecdsa_signature_t * sig;
  secp256k1_pubkey_t * pubkey;
};

#endif
