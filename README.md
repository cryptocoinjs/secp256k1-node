Global
===



verifySecetKey(sercetKey) 
-----------------------------
Verify an ECDSA secret key.

**Parameters**

**sercetKey**: Buffer, the sercet Key to verify

**Returns**: Boolean, `true` if sercet key is valid, `false` sercet key is invalid

verifyPublicKey(publicKey) 
-----------------------------
Verify an ECDSA public key.

**Parameters**

**publicKey**: Buffer, the public Key to verify

**Returns**: Boolean, `true` if public key is valid, `false` sercet key is invalid

sign(secretkey, msg, cb) 
-----------------------------
Create an ECDSA signature.

**Parameters**

**secretkey**: Buffer, a 32-byte secret key (assumed to be valid)

**msg**: Buffer, he message being signed

**cb**: function, the callback given. The callback is given the signature

**Returns**: Buffer, if no callback is given a 72-byte signature is returned

signCompact(sercetKey, msg, cb, sig, recid:) 
-----------------------------
Create a compact ECDSA signature (64 byte + recovery id). Runs asyncously
if given a callback

**Parameters**

**sercetKey**: Buffer, a 32-byte secret key (assumed to be valid)

**msg**: Buffer, the message being signed

**cb**: function, the callback which is give `err`, `sig` the

**sig**: Buffer, a 64-byte buffer repersenting the signature

**recid:**: Number, an int which is the recovery id.

**Returns**: Object, result only if no callback is given will the result be returned
   result.sigature
   result.r
   result.s
   result.recoveryID

verify(pubKey, mgs, sig) 
-----------------------------
Verify an ECDSA signature.

**Parameters**

**pubKey**: Buffer, the public key

**mgs**: Buffer, the message

**sig**: Buffer, the signature

**Returns**: Integer, 1: correct signature
   0: incorrect signature
  -1: invalid public key
  -2: invalid signature

recoverCompact(msg, sig, compressed, recid, cb) 
-----------------------------
Recover an ECDSA public key from a compact signature. In the process also verifing it.

**Parameters**

**msg**: Buffer, the message assumed to be signed

**sig**: Buffer, the signature as 64 byte buffer

**compressed**: Boolean, whether to recover a compressed or uncompressed pubkey

**recid**: Integer, the recovery id (as returned by ecdsa_sign_compact)

**cb**: function, Recover an ECDSA public key from a compact signature. In the process also verifing it.

**Returns**: Buffer, the pubkey, a 33 or 65 byte buffer

createPubKey(secKey, compressed) 
-----------------------------
Compute the public key for a secret key.

**Parameters**

**secKey**: Buffer, a 32-byte private key.

**compressed**: Boolean, whether the computed public key should be compressed

**Returns**: Buffer, a 33-byte (if compressed) or 65-byte (if uncompressed) area to store the public key.

exportPrivateKey(secertKey, compressed) 
-----------------------------
**Parameters**

**secertKey**: Buffer, 

**compressed**: Boolean, 

**Returns**: Buffer, privateKey

importPrivateKey(privateKey) 
-----------------------------
**Parameters**

**privateKey**: Buffer, 

**Returns**: Buffer, secertKey

decompressPublickey(secretKey) 
-----------------------------
**Parameters**

**secretKey**: Buffer, 

**Returns**: Buffer, 


---
