secp256k1 [![Build Status](https://travis-ci.org/wanderer/secp256k1-node.svg?branch=master)](https://travis-ci.org/wanderer/secp256k1-node)
===

This module provides native bindings to ecdsa [secp256k1](https://github.com/bitcoin/secp256k1) functions

Usage
===
```javascript

var ecdsa = require('secp256k1'),
  sr = require('secure-random'); 

var privateKey = sr.randomBuffer(32);

//a random message to sign
var msg = sr.randomBuffer(32);

//get the public key in a compressed format
var pubKey = ecdsa.createPublicKey(privateKey, true);

//sign the message
var sig = ecdsa.sign(privateKey, msg);

//verify the signature
if(ecdsa.verify(pubKey, msg, sig)){
  console.log("valid signature");
}

```

Test
===
run `npm test`
 
API
===

secp256k1.verifySecetKey(sercetKey) 
-----------------------------
Verify an ECDSA secret key.

**Parameters**

**sercetKey**: Buffer, the sercet Key to verify

**Returns**: Boolean, `true` if sercet key is valid, `false` sercet key is invalid

secp256k1.verifyPublicKey(publicKey) 
-----------------------------
Verify an ECDSA public key.

**Parameters**

**publicKey**: Buffer, the public Key to verify

**Returns**: Boolean, `true` if public key is valid, `false` sercet key is invalid

secp256k1.sign(secretkey, msg, cb) 
-----------------------------
Create an ECDSA signature.

**Parameters**

**secretkey**: Buffer, a 32-byte secret key (assumed to be valid)

**msg**: Buffer, he message being signed

**cb**: function, the callback given. The callback is given the signature

**Returns**: Buffer, if no callback is given a 72-byte signature is returned

secp256k1.signCompact(sercetKey, msg, cb) 
-----------------------------
Create a compact ECDSA signature (64 byte + recovery id). Runs asynchronously if given a callback

**Parameters**

**sercetKey**: Buffer, a 32-byte secret key (assumed to be valid)

**msg**: Buffer, the message being signed

**cb**: function, the callback which is give `err`, `sig` the  
   - param {Buffer} sig  a 64-byte buffer repersenting the signature
   - param {Number} recid an int which is the recovery id.

**Returns**: Object, result only if no callback is given will the result be returned  
   - result.sigature
   - result.r
   - result.s
   - result.recoveryID

secp256k1.verify(pubKey, mgs, sig) 
-----------------------------
Verify an ECDSA signature.  Runs asynchronously if given a callback

**Parameters**

**pubKey**: Buffer, the public key

**mgs**: Buffer, the message

**sig**: Buffer, the signature

**Returns**: Integer,  
   - 1: correct signature
   - 0: incorrect signature
   - -1: invalid public key
   - -2: invalid signature

secp256k1.recoverCompact(msg, sig, compressed, recid, cb) 
-----------------------------
Recover an ECDSA public key from a compact signature in the process also verifing it.  Runs asynchronously if given a callback

**Parameters**

**msg**: Buffer, the message assumed to be signed

**sig**: Buffer, the signature as 64 byte buffer

**compressed**: Boolean, whether to recover a compressed or uncompressed pubkey

**recid**: Integer, the recovery id (as returned by ecdsa_sign_compact)

**cb**: function, Recover an ECDSA public key from a compact signature. In the process also verifing it.

**Returns**: Buffer, the pubkey, a 33 or 65 byte buffer

secp256k1.createPubKey(secKey, compressed) 
-----------------------------
Compute the public key for a secret key.

**Parameters**

**secKey**: Buffer, a 32-byte private key.

**compressed**: Boolean, whether the computed public key should be compressed

**Returns**: Buffer, a 33-byte (if compressed) or 65-byte (if uncompressed) area to store the public key.

secp256k1.exportPrivateKey(secertKey, compressed) 
-----------------------------

**Parameters**

**secertKey**: Buffer

**compressed**: Boolean

**Returns**: Buffer, privateKey

secp256k1.importPrivateKey(privateKey) 
-----------------------------

**Parameters**

**privateKey**: Buffer, This module provides native bindings to ecdsa [secp256k1](https://github.com/bitcoin/secp256k1) functions

**Returns**: Buffer, secertKey

secp256k1.decompressPublickey(secretKey) 
-----------------------------

**Parameters**

**secretKey**: Buffer, This module provides native bindings to ecdsa [secp256k1](https://github.com/bitcoin/secp256k1) functions

**Returns**: Buffer, This module provides native bindings to ecdsa [secp256k1](https://github.com/bitcoin/secp256k1) functions


---


# NOTES
This will not work on node version 11 yet. Arrays need to have `isolates` for this.







