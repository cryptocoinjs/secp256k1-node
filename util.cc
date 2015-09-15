#include <nan.h>
#include <node.h>
using namespace v8;

#include "./secp256k1-src/include/secp256k1.h"
#include "./util.h"

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

int parse_sig(bool DER,  secp256k1_ecdsa_signature_t *sig, Local<Object> sig_buf, int recid){
  const unsigned char *sig_data = (unsigned char *) node::Buffer::Data(sig_buf);
  if(DER){
    int sig_len = node::Buffer::Length(sig_buf);
    return secp256k1_ecdsa_signature_parse_der(secp256k1ctx, sig, sig_data, sig_len);
  }else{
    return secp256k1_ecdsa_signature_parse_compact(secp256k1ctx, sig, sig_data, recid);
  }
};

Local<Object> localBuffer(char* data, int dataLen){
   return Nan::CopyBuffer(data, size_t(dataLen)).ToLocalChecked();
}

