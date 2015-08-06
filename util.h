#ifndef UTIL_H
#define UTIL_H

#include <node.h>
using namespace v8;

#include "./secp256k1-src/include/secp256k1.h"

/* secp256k1ctx context to be used for calling secp256k1 functions; it is safe
 * to use same context across all of the calls in this wrapper, as per comment
 * in "./secp256k1-src/include/secp256k1.h":
 * """Only functions that take a pointer to a non-const context require exclusive
 * access to it. Multiple functions that take a pointer to a const context may
 * run simultaneously."""
 * Since all of the below functions accept const pointer of the CTX.
 */
extern secp256k1_context_t * secp256k1ctx;

void serialize_sig(bool DER, char *& output, int *outputlen, int *recid, secp256k1_ecdsa_signature_t *sig);
int parse_sig(bool DER,  secp256k1_ecdsa_signature_t *sig, Local<Object> sig_buf, int recid=-1);

#endif
