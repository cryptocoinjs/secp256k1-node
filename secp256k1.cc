#include <nan.h>
#include <iostream>
#include <node.h>

#include "./secp256k1-src/include/secp256k1.h"
using namespace v8;

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
    int result = secp256k1_ecdsa_signature_serialize_der(secp256k1ctx, (unsigned char *)output, outputlen, sig);

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
class SignWorker : public NanAsyncWorker {
 public:
  // Constructor
  SignWorker(NanCallback *callback, const unsigned char *msg32, const unsigned char *seckey, bool DER=false)
    : NanAsyncWorker(callback), msg32(msg32), seckey(seckey), DER(DER) {}
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
    NanScope();

    char* output;
    int outputlen;
    int recid;

    serialize_sig(DER, output, &outputlen, &recid, &sig);

    Handle<Value> argv[3] = {
      NanNew<Number>(result),
      node::Buffer::New(output, outputlen),
      NanNew<Number>(recid)
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
class RecoverWorker : public NanAsyncWorker {
 public:
  // Constructor
  RecoverWorker(NanCallback *callback, const unsigned char *msg32, secp256k1_ecdsa_signature_t *sig, int compressed=true)
    : NanAsyncWorker(callback), msg32(msg32), sig(sig), compressed(compressed) {}
  // Destructor
  ~RecoverWorker() {
    delete sig;
  }

  void Execute () {
    this->result = secp256k1_ecdsa_recover(secp256k1ctx, msg32, sig, &pubkey);
  }

  void HandleOKCallback () {
    NanScope();

    unsigned char output[65];
    int outputlen;

    secp256k1_ec_pubkey_serialize(secp256k1ctx, output, &outputlen, &pubkey, compressed);

    Handle<Value> argv[] = {
      NanNew<Number>(result),
      NanNewBufferHandle((char *)output, outputlen)
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

class VerifyWorker : public NanAsyncWorker {
 public:
  // Constructor
  VerifyWorker(NanCallback *callback, const unsigned char *msg32, secp256k1_ecdsa_signature_t *sig, secp256k1_pubkey_t *pubkey)
    : NanAsyncWorker(callback), msg32(msg32), sig(sig), pubkey(pubkey) {}
  // Destructor
  ~VerifyWorker() {
    delete sig;
    delete pubkey;
  }

  void Execute () {
    result = secp256k1_ecdsa_verify(secp256k1ctx, msg32, sig, pubkey);
  }

  void HandleOKCallback () {
    NanScope();
    Handle<Value> argv[] = {
      NanNew<Number>(result),
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
  NanScope();

  //parse the argments
  const unsigned char *pubkey_data = (unsigned char *) node::Buffer::Data(args[0].As<Object>());
  const unsigned char *msg_data = (unsigned char *) node::Buffer::Data(args[1].As<Object>());
  Local<Object> sig_buf = args[2].As<Object>();
  const unsigned char *sig_data = (unsigned char *) node::Buffer::Data(sig_buf);
  int recid = args[3]->IntegerValue();
  bool DER = args[4]->BooleanValue();

  //parse the signature
  secp256k1_ecdsa_signature_t * sig = new secp256k1_ecdsa_signature_t();
  parse_sig(DER, sig, sig_buf, recid);

  //parse the public key
  int pubkey_len = node::Buffer::Length(args[0]);
  secp256k1_pubkey_t * pubkey = new secp256k1_pubkey_t();
  secp256k1_ec_pubkey_parse(secp256k1ctx, pubkey, pubkey_data, pubkey_len);

  //if there is no callback then run sync
  if(args.Length() == 5){
    int result = secp256k1_ecdsa_verify(secp256k1ctx, msg_data, sig, pubkey); 
    delete sig;
    delete pubkey;
    NanReturnValue(NanNew<Boolean>(result));
  }else{
    //if there is a callback run asyc version
    NanCallback *nanCallback = new NanCallback(args[5].As<Function>());
    VerifyWorker *worker = new VerifyWorker(nanCallback, msg_data, sig, pubkey);
    NanAsyncQueueWorker(worker);
    NanReturnUndefined();
  }
}

NAN_METHOD(Sign){
  NanScope();

  //the message that we are signing
  const unsigned char *msg_data = (unsigned char *) node::Buffer::Data(args[0].As<Object>());
  //the private key as a buffer
  const unsigned char *seckey_data = (unsigned char *) node::Buffer::Data(args[1].As<Object>());
  bool DER = args[2]->BooleanValue();

  if(args.Length() == 3){
    secp256k1_ecdsa_signature_t sig;
    int result = secp256k1_ecdsa_sign(secp256k1ctx, msg_data, &sig, seckey_data, NULL, NULL);

    if(result == 1){
      char* output;
      int outputlen;
      int recid;

      serialize_sig(DER, output, &outputlen, &recid, &sig);

      Handle<Array> results = NanNew<v8::Array>();
      results->Set(0, NanNewBufferHandle(output, outputlen));
      results->Set(1, NanNew<Number>(recid));

      delete output; //output was allocated by serialize_sig

      NanReturnValue(results); 
    }else{
      return NanThrowError("nonce invalid, try another one");
    }
  }else{
    //if there is a callback run asyc version
    NanCallback *nanCallback = new NanCallback(args[3].As<Function>());
    SignWorker* worker = new SignWorker(nanCallback, msg_data, seckey_data, DER);
    NanAsyncQueueWorker(worker);
    NanReturnUndefined();
  }
}

NAN_METHOD(Recover){
  NanScope();
  
  const unsigned char *msg = (unsigned char *) node::Buffer::Data(args[0].As<Object>());
  Local<Object> sig_buf = args[1].As<Object>();
  int recid = args[2]->IntegerValue();
  bool compressed = args[3]->IntegerValue();
  bool DER = args[4]->BooleanValue();

  //parse the signature
  secp256k1_ecdsa_signature_t * sig = new secp256k1_ecdsa_signature_t();
  parse_sig(false, sig, sig_buf, recid);

  if(args.Length() == 5){
    secp256k1_pubkey_t pubkey;
    int result = secp256k1_ecdsa_recover(secp256k1ctx, msg, sig, &pubkey);
    delete sig;
 
    if(result == 1){
      unsigned char output[65];
      int outputlen;
      secp256k1_ec_pubkey_serialize(secp256k1ctx, output, &outputlen, &pubkey, true);
      NanReturnValue(NanNewBufferHandle((char *)output, outputlen));
    }else{
      NanReturnValue(NanFalse());
    }
  }else{
    //the callback
    NanCallback* nanCallback = new NanCallback(args[5].As<Function>());
    RecoverWorker* worker = new RecoverWorker(nanCallback, msg, sig);
    NanAsyncQueueWorker(worker);
    NanReturnUndefined();
  }
}

NAN_METHOD(Seckey_Verify){
  NanScope();

  const unsigned char *data = (const unsigned char*) node::Buffer::Data(args[0]);
  int result =  secp256k1_ec_seckey_verify(secp256k1ctx, data); 
  NanReturnValue(NanNew<Number>(result)); 
}

NAN_METHOD(Pubkey_Create){
  NanScope();

  const unsigned char *seckey = (unsigned char *) node::Buffer::Data(args[0].As<Object>());
  int compressed = args[1]->IntegerValue();

  secp256k1_pubkey_t pubkey;
  int results = secp256k1_ec_pubkey_create(secp256k1ctx, &pubkey, seckey);
  if(results == 0){
    return NanThrowError("secret was invalid, try again.");
  }else{
    unsigned char output[65]; 
    int outputlen;
    secp256k1_ec_pubkey_serialize(secp256k1ctx, output, &outputlen, &pubkey, 1);
    NanReturnValue(NanNewBufferHandle((char *)output, outputlen));
  }
}

NAN_METHOD(Privkey_Import){
  NanScope();

  //the first argument should be the private key as a buffer
  Handle<Object> pk_buf = args[0].As<Object>();
  const unsigned char *pk_data = (unsigned char *) node::Buffer::Data(pk_buf);

  int pk_len = node::Buffer::Length(pk_buf);

  unsigned char sec_key[32];
  int results = secp256k1_ec_privkey_import(secp256k1ctx, sec_key, pk_data, pk_len);

  if(results == 0){
    return NanThrowError("invalid private key");
  }else{
    NanReturnValue(NanNewBufferHandle((char *)sec_key, 32));
  }
}

NAN_METHOD(Privkey_Export){
  NanScope();

  const unsigned char *sk_data = (unsigned char *) node::Buffer::Data(args[0].As<Object>());
  int compressed = args[1]->IntegerValue();

  unsigned char *privKey;
  int pk_len;
  int results = secp256k1_ec_privkey_export(secp256k1ctx, sk_data, privKey, &pk_len, compressed);
  if(results == 0){
    return NanThrowError("invalid private key");
  }else{
    NanReturnValue(NanNewBufferHandle((char *)privKey, pk_len));
  }
}

NAN_METHOD(Privkey_Tweak_Add){
  NanScope();

  //the first argument should be the private key as a buffer
  unsigned char *sk = (unsigned char *) node::Buffer::Data(args[0].As<Object>());
  const unsigned char *tweak= (unsigned char *) node::Buffer::Data(args[1].As<Object>());

  int results = secp256k1_ec_privkey_tweak_add(secp256k1ctx, sk, tweak);
  if(results == 0){
    return NanThrowError("invalid key");
  }else{
    NanReturnValue(NanNewBufferHandle((char *)sk, 32));
  }
}

NAN_METHOD(Privkey_Tweak_Mul){
  NanScope();

  //the first argument should be the private key as a buffer
  unsigned char *sk = (unsigned char *) node::Buffer::Data(args[0].As<Object>());
  const unsigned char *tweak= (unsigned char *) node::Buffer::Data(args[1].As<Object>());

  int results = secp256k1_ec_privkey_tweak_mul(secp256k1ctx, sk, tweak);
  if(results == 0){
    return NanThrowError("invalid key");
  }else{
    NanReturnValue(NanNewBufferHandle((char *)sk, 32));
  }
}

NAN_METHOD(Pubkey_Tweak_Add){
  NanScope();

  //the first argument should be the private key as a buffer
  Handle<Object> pk_buf = args[0].As<Object>();
  unsigned char *pk_data = (unsigned char *) node::Buffer::Data(pk_buf);
  const unsigned char *tweak= (unsigned char *) node::Buffer::Data( args[1].As<Object>());

  //parse the public key
  int pub_len = node::Buffer::Length(pk_buf);
  secp256k1_pubkey_t *pub_key;
  secp256k1_ec_pubkey_parse(secp256k1ctx, pub_key, pk_data, pub_len);

  int results = secp256k1_ec_pubkey_tweak_add(secp256k1ctx, pub_key, tweak);
  if(results == 0){
    return NanThrowError("invalid key");
  }else{
    NanReturnValue(NanNewBufferHandle((char *)pub_key, pub_len));
  }
}

NAN_METHOD(Pubkey_Tweak_Mul){
  NanScope();

  //the first argument should be the private key as a buffer
  Handle<Object> pk_buf = args[0].As<Object>();
  const unsigned char *pk_data = (unsigned char *) node::Buffer::Data(pk_buf);
  const unsigned char *tweak= (unsigned char *) node::Buffer::Data(args[1].As<Object>());

  //parse the public key
  int pub_len = node::Buffer::Length(pk_buf);
  secp256k1_pubkey_t pub_key;
  secp256k1_ec_pubkey_parse(secp256k1ctx, &pub_key, pk_data, pub_len);

  int results = secp256k1_ec_pubkey_tweak_mul(secp256k1ctx, &pub_key, tweak);
  if(results == 0){
    return NanThrowError("invalid key");
  }else{
    NanReturnValue(NanNewBufferHandle((char *)pub_key, pub_len));
  }
}

void Init(Handle<Object> exports) {
  secp256k1ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
  exports->Set(NanNew("sign"), NanNew<FunctionTemplate>(Sign)->GetFunction());
  exports->Set(NanNew("recover"), NanNew<FunctionTemplate>(Recover)->GetFunction());
  exports->Set(NanNew("verify"), NanNew<FunctionTemplate>(Verify)->GetFunction());
  exports->Set(NanNew("secKeyVerify"), NanNew<FunctionTemplate>(Seckey_Verify)->GetFunction());
  exports->Set(NanNew("pubKeyCreate"), NanNew<FunctionTemplate>(Pubkey_Create)->GetFunction());
  exports->Set(NanNew("privKeyExport"), NanNew<FunctionTemplate>(Privkey_Export)->GetFunction());
  exports->Set(NanNew("privKeyImport"), NanNew<FunctionTemplate>(Privkey_Import)->GetFunction());
  exports->Set(NanNew("privKeyTweakAdd"), NanNew<FunctionTemplate>(Privkey_Tweak_Add)->GetFunction());
  exports->Set(NanNew("privKeyTweakMul"), NanNew<FunctionTemplate>(Privkey_Tweak_Mul)->GetFunction());
  exports->Set(NanNew("pubKeyTweakAdd"), NanNew<FunctionTemplate>(Privkey_Tweak_Add)->GetFunction());
  exports->Set(NanNew("pubKeyTweakMul"), NanNew<FunctionTemplate>(Privkey_Tweak_Mul)->GetFunction());
}

NODE_MODULE(secp256k1, Init)
