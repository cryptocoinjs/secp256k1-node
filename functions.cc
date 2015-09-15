#include <iostream>
#include <nan.h>
#include <node.h>
#include "./util.h"
#include "./async.h"
using namespace v8;

NAN_METHOD(Verify){
  Nan::HandleScope scope;

  //parse the argments
  const unsigned char *pubkey_data = (unsigned char *) node::Buffer::Data(info[0].As<Object>());
  const unsigned char *msg_data = (unsigned char *) node::Buffer::Data(info[1].As<Object>());
  Local<Object> sig_buf = info[2].As<Object>();
  int recid = info[3]->IntegerValue();
  bool DER = info[4]->BooleanValue();

  //parse the signature
  secp256k1_ecdsa_signature_t * sig = new secp256k1_ecdsa_signature_t();
  parse_sig(DER, sig, sig_buf, recid);

  //parse the public key
  int pubkey_len = node::Buffer::Length(info[0]);
  secp256k1_pubkey_t * pubkey = new secp256k1_pubkey_t();
  int result = secp256k1_ec_pubkey_parse(secp256k1ctx, pubkey, pubkey_data, pubkey_len);

  if(result == 0){
    return Nan::ThrowError("the public key could not be parsed or is invalid");
  }

  //if there is no callback then run sync
  if(info.Length() == 5){
    int result = secp256k1_ecdsa_verify(secp256k1ctx, msg_data, sig, pubkey); 
    delete sig;
    delete pubkey;
    info.GetReturnValue().Set(Nan::New<Boolean>(result));
  }else{
    //if there is a callback run asyc version
    Nan::Callback *nanCallback = new Nan::Callback(info[5].As<Function>());
    VerifyWorker *worker = new VerifyWorker(nanCallback, msg_data, sig, pubkey);
    Nan::AsyncQueueWorker(worker);
    info.GetReturnValue().SetUndefined();
  }
}

NAN_METHOD(Sign){
  Nan::HandleScope scope;

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
      
      Local<Array> results = Nan::New<Array>();
      results->Set(0, localBuffer(output, size_t(outputlen)));
      results->Set(1, Nan::New<Number>(recid));

      delete output; //output was allocated by serialize_sig

      info.GetReturnValue().Set(results); 
    }else{
      return Nan::ThrowError("nonce invalid, try another one");
    }
  }else{
    //if there is a callback run asyc version
    Nan::Callback *nanCallback = new Nan::Callback(info[3].As<Function>());
    SignWorker* worker = new SignWorker(nanCallback, msg_data, seckey_data, DER);
    Nan::AsyncQueueWorker(worker);
    info.GetReturnValue().SetUndefined();
  }
}

NAN_METHOD(Recover){
  Nan::HandleScope scope;
  
  const unsigned char *msg = (unsigned char *) node::Buffer::Data(info[0].As<Object>());
  Local<Object> sig_buf = info[1].As<Object>();
  int recid = info[2]->IntegerValue();
  bool compressed = info[3]->IntegerValue();
  bool DER = info[4]->BooleanValue();

  //parse the signature
  secp256k1_ecdsa_signature_t * sig = new secp256k1_ecdsa_signature_t();
  parse_sig(DER, sig, sig_buf, recid);

  if(info.Length() == 5){
    secp256k1_pubkey_t pubkey;
    int result = secp256k1_ecdsa_recover(secp256k1ctx, msg, sig, &pubkey);
    delete sig;
 
    if(result == 1){
      unsigned char output[65];
      int outputlen;
      secp256k1_ec_pubkey_serialize(secp256k1ctx, output, &outputlen, &pubkey, compressed);

      info.GetReturnValue().Set(localBuffer((char *)output, size_t(outputlen)));
    }else{
      info.GetReturnValue().Set(Nan::False());
    }
  }else{
    //the callback
    Nan::Callback* nanCallback = new Nan::Callback(info[5].As<Function>());
    RecoverWorker* worker = new RecoverWorker(nanCallback, msg, sig);
    Nan::AsyncQueueWorker(worker);
    info.GetReturnValue().SetUndefined();
  }
}

NAN_METHOD(Seckey_Verify){
  Nan::HandleScope scope;

  const unsigned char *data = (const unsigned char*) node::Buffer::Data(info[0]);
  int result =  secp256k1_ec_seckey_verify(secp256k1ctx, data); 
  info.GetReturnValue().Set(Nan::New<Number>(result)); 
}

NAN_METHOD(Pubkey_Create){
  Nan::HandleScope scope;

  const unsigned char *seckey = (unsigned char *) node::Buffer::Data(info[0].As<Object>());
  int compressed = info[1]->IntegerValue();

  secp256k1_pubkey_t pubkey;
  int results = secp256k1_ec_pubkey_create(secp256k1ctx, &pubkey, seckey);
  if(results == 0){
    return Nan::ThrowError("secret was invalid, try again.");
  }else{
    unsigned char output[65]; 
    int outputlen;
    secp256k1_ec_pubkey_serialize(secp256k1ctx, output, &outputlen, &pubkey, compressed);

    info.GetReturnValue().Set(localBuffer((char *)output, size_t(outputlen)));
  }
}

NAN_METHOD(Privkey_Import){
  Nan::HandleScope scope;

  //the first argument should be the private key as a buffer
  Local<Object> privkey_buf = info[0].As<Object>();
  const unsigned char *privkey_data = (unsigned char *) node::Buffer::Data(privkey_buf);

  int privkey_len = node::Buffer::Length(privkey_buf);

  unsigned char outkey[32];
  int results = secp256k1_ec_privkey_import(secp256k1ctx, outkey, privkey_data, privkey_len);

  if(results == 0){
    return Nan::ThrowError("invalid private key");
  }else{
    info.GetReturnValue().Set(localBuffer((char *)outkey, 32));
  }
}

NAN_METHOD(Privkey_Export){
  Nan::HandleScope scope;

  const unsigned char *seckey = (unsigned char *) node::Buffer::Data(info[0].As<Object>());
  const int compressed = info[1]->IntegerValue();

  unsigned char outkey[300]; //TODO: findout the real upper limit to privkey_export
  int outkey_len;
  int results = secp256k1_ec_privkey_export(secp256k1ctx, seckey, outkey, &outkey_len, compressed);
  if(results == 0){
    return Nan::ThrowError("invalid private key");
  }else{
    info.GetReturnValue().Set(localBuffer((char *)outkey, size_t(outkey_len)));
  }
}

NAN_METHOD(Privkey_Tweak_Add){
  Nan::HandleScope scope;

  //the first argument should be the private key as a buffer
  unsigned char *seckey = (unsigned char *) node::Buffer::Data(info[0].As<Object>());
  const unsigned char *tweak= (unsigned char *) node::Buffer::Data(info[1].As<Object>());

  int results = secp256k1_ec_privkey_tweak_add(secp256k1ctx, seckey, tweak);
  if(results == 0){
    return Nan::ThrowError("invalid key");
  }else{
    info.GetReturnValue().Set(localBuffer((char *)seckey, 32));
  }
}

NAN_METHOD(Privkey_Tweak_Mul){
  Nan::HandleScope scope;

  //the first argument should be the private key as a buffer
  unsigned char *seckey = (unsigned char *) node::Buffer::Data(info[0].As<Object>());
  const unsigned char *tweak= (unsigned char *) node::Buffer::Data(info[1].As<Object>());

  int results = secp256k1_ec_privkey_tweak_mul(secp256k1ctx, seckey, tweak);
  if(results == 0){
    return Nan::ThrowError("invalid key");
  }else{
    info.GetReturnValue().Set(localBuffer((char *)seckey, 32));
  }
}

NAN_METHOD(Pubkey_Tweak_Add){
  Nan::HandleScope scope;

  //the first argument should be the private key as a buffer
  Local<Object> pk_buf = info[0].As<Object>();
  unsigned char *pk_data = (unsigned char *) node::Buffer::Data(pk_buf);
  const unsigned char *tweak= (unsigned char *) node::Buffer::Data( info[1].As<Object>());

  //parse the public key
  int pub_len = node::Buffer::Length(pk_buf);
  secp256k1_pubkey_t *pub_key;
  int results = secp256k1_ec_pubkey_parse(secp256k1ctx, pub_key, pk_data, pub_len);
  if(results == 0){
    return Nan::ThrowError("the public key could not be parsed or is invalid");
  }

  results = secp256k1_ec_pubkey_tweak_add(secp256k1ctx, pub_key, tweak);
  if(results == 0){
    return Nan::ThrowError("invalid key");
  }else{
    info.GetReturnValue().Set(localBuffer((char *)pub_key, pub_len));
  }
}

NAN_METHOD(Pubkey_Tweak_Mul){
  Nan::HandleScope scope;

  //the first argument should be the private key as a buffer
  Local<Object> pk_buf = info[0].As<Object>();
  unsigned char *pk_data = (unsigned char *) node::Buffer::Data(pk_buf);
  const unsigned char *tweak= (unsigned char *) node::Buffer::Data(info[1].As<Object>());

  //parse the public key
  int pub_len = node::Buffer::Length(pk_buf);
  secp256k1_pubkey_t *pub_key;
  int results= secp256k1_ec_pubkey_parse(secp256k1ctx, pub_key, pk_data, pub_len);
  if(results == 0){
    return Nan::ThrowError("the public key could not be parsed or is invalid");
  }

  results = secp256k1_ec_pubkey_tweak_mul(secp256k1ctx, pub_key, tweak);
  if(results == 0){
    return Nan::ThrowError("invalid key");
  }else{
    info.GetReturnValue().Set(localBuffer((char *)pub_key, pub_len));
  }
}
