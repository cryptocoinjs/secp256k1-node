#include <nan.h>
#include <iostream>
#include <node.h>

#include "./src/include/secp256k1.h"

using namespace v8;

class SignWorker : public NanAsyncWorker {
 public:
  // Constructor
  SignWorker(NanCallback *callback, const unsigned char *msg, int msg_len, const unsigned char *pk )
    : NanAsyncWorker(callback), msg(msg), pk(pk), msg_len(msg_len), sig_len(72) {}
  // Destructor
  ~SignWorker() {}

  // Executed inside the worker-thread.
  // It is not safe to access V8, or V8 data structures
  // here, so everything we need for input and output
  // should go on `this`.
  void Execute () {
    this->result = secp256k1_ecdsa_sign(this->msg, this->msg_len , this->sig , &this->sig_len, this->pk, this->pk);
  }

  // Executed when the async work is complete
  // this function will be run inside the main event loop
  // so it is safe to use V8 again
  void HandleOKCallback () {
    NanScope();
    Handle<Value> argv[] = {
      NanNew<Number>(this->result),
      NanNewBufferHandle((char *)this->sig, this->sig_len)
    };
    callback->Call(2, argv);
  }

 protected:
  int sig_len;
  int msg_len;
  int result;
  const unsigned char * msg;
  const unsigned char * pk;
  unsigned char sig[72];
};

class CompactSignWorker : public SignWorker {
 public:
  CompactSignWorker(NanCallback *callback, const unsigned char *msg, int msg_len, const unsigned char *pk )
    : SignWorker(callback, msg, msg_len, pk){}

  void Execute () {
    this->result = secp256k1_ecdsa_sign_compact(this->msg, this->msg_len , this->sig , this->pk, this->pk,  &this->sig_len);
  }

  void HandleOKCallback () {
    NanScope();
    Handle<Value> argv[] = {
      NanNew<Number>(this->result),
      NanNewBufferHandle((char *)this->sig, 64),
      NanNew<Number>(this->sig_len)
    };
    callback->Call(3, argv);
  }
};

class RecoverWorker : public NanAsyncWorker {
 public:
  // Constructor
  RecoverWorker(NanCallback *callback, const unsigned char *msg, int msg_len, const unsigned char *sig, int compressed, int rec_id)
    : NanAsyncWorker(callback), msg(msg), msg_len(msg_len), sig(sig), compressed(compressed), rec_id(rec_id) {}
  // Destructor
  ~RecoverWorker() {}

  void Execute () {
    if(this->compressed == 1){
      this->pubkey = new unsigned char[33]; 
    }else{
      this->pubkey = new unsigned char[65]; 
    }

    this->result = secp256k1_ecdsa_recover_compact(this->msg, this->msg_len, this->sig, this->pubkey, &this->pubkey_len, this->compressed, this->rec_id);
  }

  void HandleOKCallback () {
    NanScope();
    Handle<Value> argv[] = {
      NanNew<Number>(this->result),
      NanNewBufferHandle((char *)this->pubkey, this->pubkey_len)
    };
    callback->Call(2, argv);
  }

 protected:
  int rec_id;
  int compressed;
  int result;
  unsigned char * pubkey;
  int pubkey_len;
  const unsigned char * msg;
  int msg_len;
  const unsigned char * sig; 
};

class VerifyWorker : public NanAsyncWorker {
 public:
  // Constructor
  VerifyWorker(NanCallback *callback, const unsigned char *msg, int msg_len, const unsigned char *sig, int sig_len, const unsigned char *pub_key, int pub_key_len)
    : NanAsyncWorker(callback), msg(msg), msg_len(msg_len), sig(sig), sig_len(sig_len), pub_key(pub_key), pub_key_len(pub_key_len) {}
  // Destructor
  ~VerifyWorker() {}

  void Execute () {
    this->result = secp256k1_ecdsa_verify(this->msg, this->msg_len, this->sig, this->sig_len,  this->pub_key, this->pub_key_len);
  }

  void HandleOKCallback () {
    NanScope();
    Handle<Value> argv[] = {
      NanNew<Number>(this->result),
    };
    callback->Call(1, argv);
  }

 protected:
  int result;
  const unsigned char * msg;
  int msg_len;
  const unsigned char * sig;
  int sig_len; 
  const unsigned char * pub_key;
  int pub_key_len;
};

NAN_METHOD(Verify){
  NanScope();

  Local<Object> pub_buf = args[0].As<Object>();
  const unsigned char *pub_data = (unsigned char *) node::Buffer::Data(pub_buf);
  int pub_len = node::Buffer::Length(args[0]);

  Local<Object> msg_buf = args[1].As<Object>();
  const unsigned char *msg_data = (unsigned char *) node::Buffer::Data(msg_buf);
  int msg_len = node::Buffer::Length(args[1]);

  Local<Object> sig_buf = args[2].As<Object>();
  const unsigned char *sig_data = (unsigned char *) node::Buffer::Data(sig_buf);
  int sig_len = node::Buffer::Length(args[2]);

  int result = secp256k1_ecdsa_verify(msg_data, msg_len, sig_data, sig_len, pub_data, pub_len ); 

  NanReturnValue(NanNew<Number>(result));
}

NAN_METHOD(Verify_Async){
  NanScope();

  Local<Object> pub_buf = args[0].As<Object>();
  const unsigned char *pub_data = (unsigned char *) node::Buffer::Data(pub_buf);
  int pub_len = node::Buffer::Length(args[0]);

  Local<Object> msg_buf = args[1].As<Object>();
  const unsigned char *msg_data = (unsigned char *) node::Buffer::Data(msg_buf);
  int msg_len = node::Buffer::Length(args[1]);

  Local<Object> sig_buf = args[2].As<Object>();
  const unsigned char *sig_data = (unsigned char *) node::Buffer::Data(sig_buf);
  int sig_len = node::Buffer::Length(args[2]);

  Local<Function> callback = args[3].As<Function>();
  NanCallback* nanCallback = new NanCallback(callback);

  VerifyWorker* worker = new VerifyWorker(nanCallback, msg_data, msg_len, sig_data, sig_len, pub_data, pub_len);
  NanAsyncQueueWorker(worker);

  NanReturnUndefined();
}

NAN_METHOD(Sign){
  NanScope();

  //the first argument should be the private key as a buffer
  Local<Object> pk_buf = args[0].As<Object>();
  const unsigned char *pk_data = (unsigned char *) node::Buffer::Data(pk_buf);
  //the second argument is the message that we are signing
  Local<Object> msg_buf = args[1].As<Object>();
  const unsigned char *msg_data = (unsigned char *) node::Buffer::Data(msg_buf);


  unsigned char sig[72];
  int sig_len = 72;
  int msg_len = node::Buffer::Length(args[1]);

  int result = secp256k1_ecdsa_sign(msg_data, msg_len , sig , &sig_len, pk_data, pk_data);
  NanReturnValue(NanNewBufferHandle((char *)sig, sig_len));
}

NAN_METHOD(Sign_Async){

  NanScope();
  //the first argument should be the private key as a buffer
  Local<Object> pk_buf = args[0].As<Object>();
  const unsigned char *pk_data = (unsigned char *) node::Buffer::Data(pk_buf);
  //the second argument is the message that we are signing
  Local<Object> msg_buf = args[1].As<Object>();
  const unsigned char *msg_data = (unsigned char *) node::Buffer::Data(msg_buf);

  Local<Function> callback = args[2].As<Function>();
  NanCallback* nanCallback = new NanCallback(callback);

  int msg_len = node::Buffer::Length(args[1]);

  SignWorker* worker = new SignWorker(nanCallback, msg_data, msg_len, pk_data);
  NanAsyncQueueWorker(worker);

  NanReturnUndefined();
}

NAN_METHOD(Sign_Compact){

  NanScope();

  Local<Object> seckey_buf = args[0].As<Object>();
  const unsigned char *seckey_data = (unsigned char *) node::Buffer::Data(seckey_buf);
  int sec_len = node::Buffer::Length(args[0]);

  Local<Object> msg_buf = args[1].As<Object>();
  const unsigned char *msg_data = (unsigned char *) node::Buffer::Data(msg_buf);
  int msg_len = node::Buffer::Length(args[1]);

  unsigned char sig[64];
  int rec_id;

  //TODO: change the nonce
  int valid_nonce = secp256k1_ecdsa_sign_compact(msg_data, msg_len, sig, seckey_data, seckey_data, &rec_id );

  Local<Array> array = Array::New(3);
  array->Set(0, Integer::New(valid_nonce));
  array->Set(1, Integer::New(rec_id));
  array->Set(2, NanNewBufferHandle((char *)sig, 64));

  NanReturnValue(array);
}

NAN_METHOD(Sign_Compact_Async){
  NanScope();
  //the first argument should be the private key as a buffer
  Local<Object> pk_buf = args[0].As<Object>();
  const unsigned char *pk_data = (unsigned char *) node::Buffer::Data(pk_buf);
  //the second argument is the message that we are signing
  Local<Object> msg_buf = args[1].As<Object>();
  const unsigned char *msg_data = (unsigned char *) node::Buffer::Data(msg_buf);

  Local<Function> callback = args[2].As<Function>();
  NanCallback* nanCallback = new NanCallback(callback);

  int msg_len = node::Buffer::Length(args[1]);

  CompactSignWorker* worker = new CompactSignWorker(nanCallback, msg_data, msg_len, pk_data);
  NanAsyncQueueWorker(worker);

  NanReturnUndefined();
}

NAN_METHOD(Recover_Compact){

  NanScope();
  
  Local<Object> msg_buf = args[0].As<Object>();
  const unsigned char *msg = (unsigned char *) node::Buffer::Data(msg_buf);
  int msg_len = node::Buffer::Length(args[0]);

  Local<Object> sig_buf = args[1].As<Object>();
  const unsigned char *sig = (unsigned char *) node::Buffer::Data(sig_buf);
  //todo sig len has to be 64
  int sig_len = node::Buffer::Length(args[1]);

  Local<Number> compressed = args[2].As<Number>();
  int int_compressed = compressed->IntegerValue();

  Local<Number> rec_id = args[3].As<Number>();
  int int_rec_id = rec_id->IntegerValue();

  unsigned char *pubKey;
  if(int_compressed == 1){
    pubKey = new unsigned char[33]; 
  }else{
    pubKey = new unsigned char[65]; 
  }

  int pubKeyLen;

  secp256k1_ecdsa_recover_compact(msg, msg_len, sig, pubKey, &pubKeyLen, int_compressed, int_rec_id);

  NanReturnValue(NanNewBufferHandle((char *)pubKey, pubKeyLen));
}

NAN_METHOD(Recover_Compact_Async){

  NanScope();
  
  //the message
  Local<Object> msg_buf = args[0].As<Object>();
  const unsigned char *msg = (unsigned char *) node::Buffer::Data(msg_buf);
  int msg_len = node::Buffer::Length(args[0]);

  //the signature length
  Local<Object> sig_buf = args[1].As<Object>();
  const unsigned char *sig = (unsigned char *) node::Buffer::Data(sig_buf);
  //todo sig len needs tobe 64
  int sig_len = node::Buffer::Length(args[1]);

  //to compress or not?
  Local<Number> compressed = args[2].As<Number>();
  int int_compressed = compressed->IntegerValue();

  //the rec_id
  Local<Number> rec_id = args[3].As<Number>();
  int int_rec_id = rec_id->IntegerValue();

  //the callback
  Local<Function> callback = args[4].As<Function>();
  NanCallback* nanCallback = new NanCallback(callback);

  RecoverWorker* worker = new RecoverWorker(nanCallback, msg, msg_len, sig, int_compressed, int_rec_id);
  NanAsyncQueueWorker(worker);

  NanReturnUndefined();
}

NAN_METHOD(Seckey_Verify){
  NanScope();

  const unsigned char *data = (const unsigned char*) node::Buffer::Data(args[0]);
  int result =  secp256k1_ecdsa_seckey_verify(data); 
  NanReturnValue(NanNew<Number>(result)); 
}

NAN_METHOD(Pubkey_Verify){

  NanScope();
  
  Local<Object> pub_buf = args[0].As<Object>();
  const unsigned char *pub_key = (unsigned char *) node::Buffer::Data(pub_buf);
  int pub_key_len = node::Buffer::Length(args[0]);

  int result = secp256k1_ecdsa_pubkey_verify(pub_key, pub_key_len);

  NanReturnValue(NanNew<Number>(result)); 
}

NAN_METHOD(Pubkey_Create){
  NanScope();

  Handle<Object> pk_buf = args[0].As<Object>();
  const unsigned char *pk_data = (unsigned char *) node::Buffer::Data(pk_buf);

  Local<Number> l_compact = args[1].As<Number>();
  int compact = l_compact->IntegerValue();
  int pubKeyLen;

  unsigned char *pubKey;
  if(compact == 1){
    pubKey = new unsigned char[33]; 
  }else{
    pubKey = new unsigned char[65]; 
  }

  secp256k1_ecdsa_pubkey_create(pubKey,&pubKeyLen, pk_data, compact );
  NanReturnValue(NanNewBufferHandle((char *)pubKey, pubKeyLen));
}

NAN_METHOD(Pubkey_Decompress){
  NanScope();

  //the first argument should be the private key as a buffer
  Local<Object> pk_buf = args[0].As<Object>();
  unsigned char *pk_data = (unsigned char *) node::Buffer::Data(pk_buf);

  int pk_len = node::Buffer::Length(args[0]);

  int results = secp256k1_ecdsa_pubkey_decompress(pk_data, &pk_len);

  NanReturnValue(NanNewBufferHandle((char *)pk_data, pk_len));
}


NAN_METHOD(Privkey_Import){
  NanScope();

  //the first argument should be the private key as a buffer
  Handle<Object> pk_buf = args[0].As<Object>();
  const unsigned char *pk_data = (unsigned char *) node::Buffer::Data(pk_buf);

  int pk_len = node::Buffer::Length(args[0]);

  unsigned char *sec_key;
  int results = secp256k1_ecdsa_privkey_import(sec_key, pk_data, pk_len);

  NanReturnValue(NanNewBufferHandle((char *)sec_key, 32));
}

NAN_METHOD(Privkey_Export){
  NanScope();

  //the first argument should be the private key as a buffer
  Handle<Object> sk_buf = args[0].As<Object>();
  const unsigned char *sk_data = (unsigned char *) node::Buffer::Data(sk_buf);

  Local<Number> l_compressed = args[1].As<Number>();
  int compressed = l_compressed->IntegerValue();

  unsigned char *privKey;
  int pk_len;
  int results = secp256k1_ecdsa_privkey_export(sk_data, privKey, &pk_len, compressed);

  NanReturnValue(NanNewBufferHandle((char *)privKey, pk_len));
}

void Init(Handle<Object> exports) {
  secp256k1_start();
  exports->Set(NanNew("seckeyVerify"), NanNew<FunctionTemplate>(Seckey_Verify)->GetFunction());
  exports->Set(NanNew("sign"), NanNew<FunctionTemplate>(Sign)->GetFunction());
  exports->Set(NanNew("signAsync"), NanNew<FunctionTemplate>(Sign_Async)->GetFunction());
  exports->Set(NanNew("signCompact"), NanNew<FunctionTemplate>(Sign_Compact)->GetFunction());
  exports->Set(NanNew("signCompactAsync"), NanNew<FunctionTemplate>(Sign_Compact_Async)->GetFunction());
  exports->Set(NanNew("recoverCompact"), NanNew<FunctionTemplate>(Recover_Compact)->GetFunction());
  exports->Set(NanNew("recoverCompactAsync"), NanNew<FunctionTemplate>(Recover_Compact_Async)->GetFunction());
  exports->Set(NanNew("verify"), NanNew<FunctionTemplate>(Verify)->GetFunction());
  exports->Set(NanNew("verifyAsync"), NanNew<FunctionTemplate>(Verify_Async)->GetFunction());
  exports->Set(NanNew("secKeyVerify"), NanNew<FunctionTemplate>(Seckey_Verify)->GetFunction());
  exports->Set(NanNew("pubKeyVerify"), NanNew<FunctionTemplate>(Pubkey_Verify)->GetFunction());
  exports->Set(NanNew("pubKeyCreate"), NanNew<FunctionTemplate>(Pubkey_Create)->GetFunction());
  exports->Set(NanNew("pubKeyDecompress"), NanNew<FunctionTemplate>(Pubkey_Decompress)->GetFunction());
  exports->Set(NanNew("privKeyExport"), NanNew<FunctionTemplate>(Privkey_Export)->GetFunction());
  exports->Set(NanNew("privKeyImport"), NanNew<FunctionTemplate>(Privkey_Import)->GetFunction());
}

NODE_MODULE(secp256k1, Init)
