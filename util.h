#ifndef UTIL_H
#define UTIL_H

#include <node.h>
using namespace v8;

#include "./secp256k1-src/include/secp256k1.h"
#include "./secp256k1-src/include/secp256k1_recovery.h"

/* secp256k1ctx context to be used for calling secp256k1 functions; it is safe
 * to use same context across all of the calls in this wrapper, as per comment
 * in "./secp256k1-src/include/secp256k1.h":
 * """Only functions that take a pointer to a non-const context require exclusive
 * access to it. Multiple functions that take a pointer to a const context may
 * run simultaneously."""
 * Since all of the below functions accept const pointer of the CTX.
 */
extern secp256k1_context * secp256k1ctx;

void serialize_sig(bool DER, char *& output, size_t *outputlen, int *recid, unsigned char *sig);
int parse_sig(bool DER, secp256k1_ecdsa_signature *sig, Local<Object> sig_buf, int recid=-1);
Local<Object> localBuffer(char* data, int dataLen);

#endif
