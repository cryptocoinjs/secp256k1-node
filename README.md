SYNOPSIS [![Build Status](https://travis-ci.org/wanderer/secp256k1-node.svg?branch=master)](https://travis-ci.org/wanderer/secp256k1-node)
===

This module provides native bindings to ecdsa [secp256k1](https://github.com/bitcoin/secp256k1) functions.   
This library is experimental, so use at your own risk. Works on node version 0.11 or greater.

INSTALL
===
If you have gmp installed secp256k1 will use it. Otherwise it should fallback to openssl.
* arch `pacman -S gmp`
* ubuntu `sudo apt-get install libgmp-dev`

##### from npm

`npm install secp256k1`   

##### from git

`git clone git@github.com:wanderer/secp256k1-node.git`  
`cd secp256k1-node`  
`npm install` 

BROWSER
===
If you want an compatiable API use [secp256k1-browserify](https://github.com/wanderer/secp256k1-browserify). Or use [elliptic](https://github.com/indutny/elliptic) directly

USAGE
===
```javascript

var ecdsa = require('secp256k1')
var crypto = require('crypto')

var privateKey = crypto.randomBytes(32)
//a random message to sign
var msg = crypto.randomBytes(32)

//get the public key in a compressed format
var pubKey = ecdsa.createPublicKey(privateKey, true)

//sign the message
var sig = ecdsa.sign(msg, privateKey)

//verify the signature
if(ecdsa.verify(msg, sig, pubKey)){
  console.log("valid signature")
}

```

TEST
===
run `npm test`
 
API
===
**Signature**
All functions that take signatures can take two formats
* DER - which should be a repersented as an `Buffer`
* Compact - which should be an `Object` with the following
  - `signature` - a `Buffer`
  - `recovery` - an `Integer` for the recovery id

secp256k1.verifySecretKey(secretKey) 
-----------------------------
Verify an ECDSA secret key.

**Parameters**

* secretKey - `Buffer`, the secret Key to verify

**Returns**: `Boolean`, `true` if secret key is valid, `false` secret key is invalid

secp256k1.verifyPublicKey(publicKey) 
-----------------------------
Verify an ECDSA public key.

**Parameters**

* publicKey - `Buffer`, the public Key to verify

**Returns**: `Boolean`, `true` if public key is valid, `false` secret key is invalid

secp256k1.sign(msg, secretkey, [DER], [cb]) 
-----------------------------
Create an ECDSA signature.

**Parameters**

* msg - `Buffer`,  a 32-byte message hash being signed 
* secretkey - `Buffer`, a 32-byte secret key (assumed to be valid)
* DER - `Boolean`, **Optional**  if `true` the signature produced will be in DER format. Defaults to `false`
* cb - `function`, **Optional** the callback. The callback is given the signature. If no callback is given the function will run sync.

**Returns**:

* if `DER` a `Buffer`, if no callback is given a 72-byte signature is returned  
* else an compact siganture `Object`

secp256k1.verify(mgs, sig, pubKey, [cb]) 
-----------------------------
Verify an ECDSA signature.  Runs asynchronously if given a callback

**Parameters**
* mgs - `Buffer`, the 32-byte message hash being verified
* sig - `Buffer`, the signature being verified
* pubKey - `Buffer`, the public key
* cb - a callback if you want to run async
 
**Returns**: Integer,  
   - true correct signature
   - false incorrect signature

secp256k1.recover(msg, sig, compressed, [cb]) 
-----------------------------
Recover an ECDSA public key from a compact signature in the process also verifing it.  Runs asynchronously if given a callback

**Parameters**
* msg - `Buffer`, the message assumed to be signed
* sig - `Buffer`, the signature
* compressed - `Boolean`, whether to recover a compressed or uncompressed pubkey. Defaults to `true`
* cb - `function`, Recover an ECDSA public key from a compact signature. In the process also verifing it.

**Returns**: Buffer, the pubkey, a 33 or 65 byte buffer

secp256k1.createPublicKey(secKey, compressed) 
-----------------------------
Compute the public key for a secret key.

**Parameters**
* secKey - `Buffer`, a 32-byte private key.
* compressed - `Boolean`, whether the computed public key should be compressed

**Returns**: Buffer, a 33-byte (if compressed) or 65-byte (if uncompressed).

secp256k1.exportPrivateKey(secretKey, compressed) 
-----------------------------

**Parameters**
* secretKey - `Buffer`
* compressed - `Boolean`

** Returns**: Buffer, privateKey

secp256k1.importPrivateKey(privateKey) 
-----------------------------

**Parameters**
* privateKey - `Buffer`

**Returns**: `Buffer`, secretKey

secp256k1.privKeyTweakAdd(secretKey) 
-----------------------------
**Parameters**
* privateKey - `Buffer`
* tweak - `Buffer`

**Returns**: `Buffer`

secp256k1.privKeyTweakMul(privateKey, tweak) 
-----------------------------
**Parameters**
* privateKey - `Buffer`
* tweak - `Buffer`

**Returns**: Buffer


LICENSE
-----------------------------
MIT
