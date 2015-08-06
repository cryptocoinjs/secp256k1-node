#include <nan.h>
#include <iostream>
#include <node.h>

#include "./secp256k1-src/include/secp256k1.h"
using v8::Function;
using v8::Local;
using v8::Number;
using v8::Boolean;
using v8::Value;
using v8::Object;
using Nan::AsyncWorker;
using Nan::Callback;
using Nan::HandleScope;
using Nan::New;

/* secp256k1ctx context to be used for calling secp256k1 functions; it is safe
 * to use same context across all of the calls in this wrapper, as per comment
 * in "./secp256k1-src/include/secp256k1.h":
 * """Only functions that take a pointer to a non-const context require exclusive
 * access to it. Multiple functions that take a pointer to a const context may
 * run simultaneously."""
 * Since all of the below functions accept const pointer of the CTX.
 */
secp256k1_context_t * secp256k1ctx;

//helper function to serialize and parse signatures
void serialize_sig(bool DER, char *& output, int *outputlen, int *recid, secp256k1_ecdsa_signature_t *sig){
  /* unsigned char sig_out */
  if(DER){
    output = new char[72];
    *outputlen = 72;
    secp256k1_ecdsa_signature_serialize_der(secp256k1ctx, (unsigned char *)output, outputlen, sig);

  }else{
    *outputlen = 64;
    output = new char[64];
    secp256k1_ecdsa_signature_serialize_compact(secp256k1ctx, (unsigned char *)output, recid, sig);

  }
};

int parse_sig(bool DER,  secp256k1_ecdsa_signature_t *sig, Local<Object> sig_buf, int recid=-1){
  const unsigned char *sig_data = (unsigned char *) node::Buffer::Data(sig_buf);
  if(DER){
    int sig_len = node::Buffer::Length(sig_buf);
    return secp256k1_ecdsa_signature_parse_der(secp256k1ctx, sig, sig_data, sig_len);
  }else{
    return secp256k1_ecdsa_signature_parse_compact(secp256k1ctx, sig, sig_data, recid);
  }
};


//Create a async Signature
class SignWorker : public AsyncWorker {
 public:
  // Constructor
  SignWorker(Callback *callback, const unsigned char *msg32, const unsigned char *seckey, bool DER=false)
    : AsyncWorker(callback), msg32(msg32), seckey(seckey), DER(DER) {}
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
    HandleScope scope;

    char* output;
    int outputlen;
    int recid;

    serialize_sig(DER, output, &outputlen, &recid, &sig);

    Local<Value> argv[3] = {
      New<Number>(result),
      node::Buffer::New(output, outputlen),
      New<Number>(recid)
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
class RecoverWorker : public AsyncWorker {
 public:
  // Constructor
  RecoverWorker(Callback *callback, const unsigned char *msg32, secp256k1_ecdsa_signature_t *sig, int compressed=true)
    : AsyncWorker(callback), msg32(msg32), sig(sig), compressed(compressed) {}
  // Destructor
  ~RecoverWorker() {
    delete sig;
  }

  void Execute () {
    this->result = secp256k1_ecdsa_recover(secp256k1ctx, msg32, sig, &pubkey);
  }

  void HandleOKCallback () {
    HandleScope scope;

    unsigned char output[65];
    int outputlen;

    secp256k1_ec_pubkey_serialize(secp256k1ctx, output, &outputlen, &pubkey, compressed);

    Local<Value> argv[] = {
      New<Number>(result),
      node::Buffer::New((char *)output, outputlen)
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

class VerifyWorker : public AsyncWorker {
 public:
  // Constructor
  VerifyWorker(Callback *callback, const unsigned char *msg32, secp256k1_ecdsa_signature_t *sig, secp256k1_pubkey_t *pubkey)
    : AsyncWorker(callback), msg32(msg32), sig(sig), pubkey(pubkey) {}
  // Destructor
  ~VerifyWorker() {
    delete sig;
    delete pubkey;
  }

  void Execute () {
    result = secp256k1_ecdsa_verify(secp256k1ctx, msg32, sig, pubkey);
  }

  void HandleOKCallback () {
    HandleScope scope;
    Local<Value> argv[] = {
      New<Number>(result),
    };
    callback->Call(1, argv);
  }

 protected:
  int result;
  const unsigned char * msg32;
  secp256k1_ecdsa_signature_t * sig;
  secp256k1_pubkey_t * pubkey;
};

NAN_METHOD(Verify){
  HandleScope scope;

  //parse the argments
  const unsigned char *pubkey_data = (unsigned char *) node::Buffer::Data(info[0].As<Object>());
  const unsigned char *msg_data = (unsigned char *) node::Buffer::Data(info[1].As<Object>());
  Local<Object> sig_buf = info[2].As<Object>();
  const unsigned char *sig_data = (unsigned char *) node::Buffer::Data(sig_buf);
  int recid = info[3]->IntegerValue();
  bool DER = info[4]->BooleanValue();

  //parse the signature
  secp256k1_ecdsa_signature_t * sig = new secp256k1_ecdsa_signature_t();
  parse_sig(DER, sig, sig_buf, recid);

  //parse the public key
  int pubkey_len = node::Buffer::Length(info[0]);
  secp256k1_pubkey_t * pubkey = new secp256k1_pubkey_t();
  secp256k1_ec_pubkey_parse(secp256k1ctx, pubkey, pubkey_data, pubkey_len);

  //if there is no callback then run sync
  if(info.Length() == 5){
    int result = secp256k1_ecdsa_verify(secp256k1ctx, msg_data, sig, pubkey); 
    delete sig;
    delete pubkey;
    info.GetReturnValue().Set(New<Boolean>(result));
  }else{
    //if there is a callback run asyc version
    Callback *nanCallback = new Callback(info[5].As<Function>());
    VerifyWorker *worker = new VerifyWorker(nanCallback, msg_data, sig, pubkey);
    Nan::AsyncQueueWorker(worker);
    info.GetReturnValue().SetUndefined();
  }
}

NAN_METHOD(Sign){
  HandleScope scope;

  //the message that we are signing
  const unsigned char *msg_data = (unsigned char *) node::Buffer::Data(info[0].As<Object>());
  //the private key as a buffer
  const unsigned char *seckey_data = (unsigned char *) node::Buffer::Data(info[1].As<Object>());
  bool DER = info[2]->BooleanValue();

  if(info.Length() == 3){
    secp256k1_ecdsa_signature_t sig;
    int result = secp256k1_ecdsa_sign(secp256k1ctx, msg_data, &sig, seckey_data, NULL, NULL);

    if(result == 1){
      char* output;
      int outputlen;
      int recid;

      serialize_sig(DER, output, &outputlen, &recid, &sig);

      Local<v8::Array> results = New<v8::Array>();
      results->Set(0, node::Buffer::New(output, outputlen));
      results->Set(1, New<Number>(recid));

      delete output; //output was allocated by serialize_sig

      info.GetReturnValue().Set(results); 
    }else{
      return Nan::ThrowError("nonce invalid, try another one");
    }
  }else{
    //if there is a callback run asyc version
    Callback *nanCallback = new Callback(info[3].As<Function>());
    SignWorker* worker = new SignWorker(nanCallback, msg_data, seckey_data, DER);
    Nan::AsyncQueueWorker(worker);
    info.GetReturnValue().SetUndefined();
  }
}

NAN_METHOD(Recover){
  HandleScope scope;
  
  const unsigned char *msg = (unsigned char *) node::Buffer::Data(info[0].As<Object>());
  Local<Object> sig_buf = info[1].As<Object>();
  int recid = info[2]->IntegerValue();
  bool compressed = info[3]->IntegerValue();
  bool DER = info[4]->BooleanValue();

  //parse the signature
  secp256k1_ecdsa_signature_t * sig = new secp256k1_ecdsa_signature_t();
  parse_sig(false, sig, sig_buf, recid);

  if(info.Length() == 5){
    secp256k1_pubkey_t pubkey;
    int result = secp256k1_ecdsa_recover(secp256k1ctx, msg, sig, &pubkey);
    delete sig;
 
    if(result == 1){
      unsigned char output[65];
      int outputlen;
      secp256k1_ec_pubkey_serialize(secp256k1ctx, output, &outputlen, &pubkey, true);
      info.GetReturnValue().Set(node::Buffer::New((char *)output, outputlen));
    }else{
      info.GetReturnValue().Set(Nan::False());
    }
  }else{
    //the callback
    Callback* nanCallback = new Callback(info[5].As<Function>());
    RecoverWorker* worker = new RecoverWorker(nanCallback, msg, sig);
    Nan::AsyncQueueWorker(worker);
    info.GetReturnValue().SetUndefined();
  }
}

NAN_METHOD(Seckey_Verify){
  HandleScope scope;

  const unsigned char *data = (const unsigned char*) node::Buffer::Data(info[0]);
  int result =  secp256k1_ec_seckey_verify(secp256k1ctx, data); 
  info.GetReturnValue().Set(New<Number>(result)); 
}

NAN_METHOD(Pubkey_Create){
  HandleScope scope;

  const unsigned char *seckey = (unsigned char *) node::Buffer::Data(info[0].As<Object>());
  int compressed = info[1]->IntegerValue();

  secp256k1_pubkey_t pubkey;
  int results = secp256k1_ec_pubkey_create(secp256k1ctx, &pubkey, seckey);
  if(results == 0){
    return Nan::ThrowError("secret was invalid, try again.");
  }else{
    unsigned char output[65]; 
    int outputlen;
    secp256k1_ec_pubkey_serialize(secp256k1ctx, output, &outputlen, &pubkey, 1);
    info.GetReturnValue().Set(node::Buffer::New((char *)output, outputlen));
  }
}

NAN_METHOD(Privkey_Import){
  HandleScope scope;

  //the first argument should be the private key as a buffer
  Local<Object> privkey_buf = info[0].As<Object>();
  const unsigned char *privkey_data = (unsigned char *) node::Buffer::Data(privkey_buf);

  int privkey_len = node::Buffer::Length(privkey_buf);

  unsigned char outkey[32];
  int results = secp256k1_ec_privkey_import(secp256k1ctx, outkey, privkey_data, privkey_len);

  if(results == 0){
    return Nan::ThrowError("invalid private key");
  }else{
    info.GetReturnValue().Set(node::Buffer::New((char *)outkey, 32));
  }
}

NAN_METHOD(Privkey_Export){
  HandleScope scope;

  const unsigned char *seckey = (unsigned char *) node::Buffer::Data(info[0].As<Object>());
  const int compressed = info[1]->IntegerValue();

  unsigned char outkey[300]; //TODO: findout the real upper limit to privkey_export
  int outkey_len;
  int results = secp256k1_ec_privkey_export(secp256k1ctx, seckey, outkey, &outkey_len, compressed);
  if(results == 0){
    return Nan::ThrowError("invalid private key");
  }else{
    info.GetReturnValue().Set(node::Buffer::New((char *)outkey, outkey_len));
  }
}

NAN_METHOD(Privkey_Tweak_Add){
  HandleScope scope;

  //the first argument should be the private key as a buffer
  unsigned char *seckey = (unsigned char *) node::Buffer::Data(info[0].As<Object>());
  const unsigned char *tweak= (unsigned char *) node::Buffer::Data(info[1].As<Object>());

  int results = secp256k1_ec_privkey_tweak_add(secp256k1ctx, seckey, tweak);
  if(results == 0){
    return Nan::ThrowError("invalid key");
  }else{
    info.GetReturnValue().Set(node::Buffer::New(((char *)seckey, 32)));
  }
}

NAN_METHOD(Privkey_Tweak_Mul){
  HandleScope scope;

  //the first argument should be the private key as a buffer
  unsigned char *seckey = (unsigned char *) node::Buffer::Data(info[0].As<Object>());
  const unsigned char *tweak= (unsigned char *) node::Buffer::Data(info[1].As<Object>());

  int results = secp256k1_ec_privkey_tweak_mul(secp256k1ctx, seckey, tweak);
  if(results == 0){
    return Nan::ThrowError("invalid key");
  }else{
    info.GetReturnValue().Set(node::Buffer::New((char *)seckey, 32));
  }
}

NAN_METHOD(Pubkey_Tweak_Add){
  HandleScope scope;

  //the first argument should be the private key as a buffer
  Local<Object> pk_buf = info[0].As<Object>();
  unsigned char *pk_data = (unsigned char *) node::Buffer::Data(pk_buf);
  const unsigned char *tweak= (unsigned char *) node::Buffer::Data( info[1].As<Object>());

  //parse the public key
  int pub_len = node::Buffer::Length(pk_buf);
  secp256k1_pubkey_t *pub_key;
  secp256k1_ec_pubkey_parse(secp256k1ctx, pub_key, pk_data, pub_len);

  int results = secp256k1_ec_pubkey_tweak_add(secp256k1ctx, pub_key, tweak);
  if(results == 0){
    return Nan::ThrowError("invalid key");
  }else{
    info.GetReturnValue().Set(node::Buffer::New((char *)pub_key, pub_len));
  }
}

NAN_METHOD(Pubkey_Tweak_Mul){
  HandleScope scope;

  //the first argument should be the private key as a buffer
  Local<Object> pk_buf = info[0].As<Object>();
  unsigned char *pk_data = (unsigned char *) node::Buffer::Data(pk_buf);
  const unsigned char *tweak= (unsigned char *) node::Buffer::Data(info[1].As<Object>());

  //parse the public key
  int pub_len = node::Buffer::Length(pk_buf);
  secp256k1_pubkey_t *pub_key;
  secp256k1_ec_pubkey_parse(secp256k1ctx, pub_key, pk_data, pub_len);

  int results = secp256k1_ec_pubkey_tweak_mul(secp256k1ctx, pub_key, tweak);
  if(results == 0){
    return Nan::ThrowError("invalid key");
  }else{
    info.GetReturnValue().Set(node::Buffer::New((char *)pub_key, pub_len));
  }
}

NAN_MODULE_INIT(Init){ 
  secp256k1ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

  Nan::Set(target, New<v8::String>("sign").ToLocalChecked(), New<v8::FunctionTemplate>(Sign)->GetFunction());
  Nan::Set(target, New<v8::String>("recover").ToLocalChecked(), New<v8::FunctionTemplate>(Recover)->GetFunction());
  Nan::Set(target, New<v8::String>("verify").ToLocalChecked(), New<v8::FunctionTemplate>(Verify)->GetFunction());
  Nan::Set(target, New<v8::String>("secKeyVerify").ToLocalChecked(), New<v8::FunctionTemplate>(Seckey_Verify)->GetFunction());
  Nan::Set(target, New<v8::String>("pubKeyCreate").ToLocalChecked(), New<v8::FunctionTemplate>(Pubkey_Create)->GetFunction());
  Nan::Set(target, New<v8::String>("privKeyExport").ToLocalChecked(), New<v8::FunctionTemplate>(Privkey_Export)->GetFunction());
  Nan::Set(target, New<v8::String>("privKeyImport").ToLocalChecked(), New<v8::FunctionTemplate>(Privkey_Import)->GetFunction());
  Nan::Set(target, New<v8::String>("privKeyTweakAdd").ToLocalChecked(), New<v8::FunctionTemplate>(Privkey_Tweak_Add)->GetFunction());
  Nan::Set(target, New<v8::String>("privKeyTweakMul").ToLocalChecked(), New<v8::FunctionTemplate>(Privkey_Tweak_Mul)->GetFunction());
  Nan::Set(target, New<v8::String>("pubKeyTweakAdd").ToLocalChecked(), New<v8::FunctionTemplate>(Pubkey_Tweak_Add)->GetFunction());
  Nan::Set(target, New<v8::String>("pubKeyTweakMul").ToLocalChecked(), New<v8::FunctionTemplate>(Pubkey_Tweak_Mul)->GetFunction());
}
NODE_MODULE(secp256k1, Init)
