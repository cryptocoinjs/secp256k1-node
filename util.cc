#include <nan.h>
#include <node.h>
using namespace v8;

#include "./util.h"

secp256k1_context * secp256k1ctx;

//helper function to serialize and parse signatures
void serialize_sig(bool DER, char *& output, size_t *outputlen, int *recid, unsigned char *sig){
  /* unsigned char sig_out */
  if(DER){
    output = new char[72];
    *outputlen = 72;
    secp256k1_ecdsa_signature_serialize_der(secp256k1ctx, (unsigned char *)output, outputlen, (secp256k1_ecdsa_signature *)sig);

  }else{
    *outputlen = 64;
    output = new char[64];
    secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1ctx, (unsigned char *)output, recid, (secp256k1_ecdsa_recoverable_signature *)sig);

  }
};

int parse_sig(bool DER, secp256k1_ecdsa_signature *sig, Local<Object> sig_buf, int recid){
  const unsigned char *sig_data = (unsigned char *) node::Buffer::Data(sig_buf);
  if(DER){
    int sig_len = node::Buffer::Length(sig_buf);
    return secp256k1_ecdsa_signature_parse_der(secp256k1ctx, sig, sig_data, sig_len);
  }else{
    secp256k1_ecdsa_recoverable_signature sigin;
    if (secp256k1_ecdsa_recoverable_signature_parse_compact(secp256k1ctx, &sigin, sig_data, recid) == 0) {
      return 0;
    }

    return secp256k1_ecdsa_recoverable_signature_convert(secp256k1ctx, sig, &sigin);
  }
};

Local<Object> localBuffer(char* data, int dataLen){
   return Nan::CopyBuffer(data, size_t(dataLen)).ToLocalChecked();
}

