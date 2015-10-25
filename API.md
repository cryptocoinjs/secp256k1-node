# API Reference (v0.2.x)

- [`.secretKeyVerify(Buffer secretKey)`](#secretkeyverifybuffer-secretkey---boolean)
- [`.secretKeyExport(Buffer secretKey)`](#secretkeyexportbuffer-secretkey---buffer)
- [`.secretKeyImport(Buffer secretKey [, Boolean compressed = true])`](#secretkeyimportbuffer-secretkey--boolean-compressed--true---buffer)
- [`.secretKeyTweakAdd(Buffer secretKey, Buffer tweak)`](#secretkeytweakaddbuffer-secretkey-buffer-tweak---buffer)
- [`.secretKeyTweakMul(Buffer secretKey, Buffer tweak)`](#secretkeytweakmulbuffer-secretkey-buffer-tweak---buffer)
- [`.publicKeyCreate(Buffer secretKey [, Boolean compressed = true])`](#publickeycreatebuffer-secretkey--boolean-compressed--true---buffer)
- [`.publicKeyConvert(Buffer publicKey [, Boolean compressed = true])`](#publickeyconvertbuffer-publickey--boolean-compressed--true---buffer)
- [`.publicKeyVerify(Buffer publicKey)`](#publickeyverifybuffer-publickey---boolean)
- [`.publicKeyTweakAdd(Buffer publicKey, Buffer tweak)`](#publickeytweakaddbuffer-publickey-buffer-tweak---buffer)
- [`.publicKeyTweakMul(Buffer publicKey, Buffer tweak)`](#publickeytweakmulbuffer-publickey-buffer-tweak---buffer)
- [`.signatureNormalize(Buffer signature)`](#signaturenormalizebuffer-signature---buffer)
- [`.signatureExport(Buffer signature)`](#signatureexportbuffer-signature---buffer)
- [`.signatureImport(Buffer signature)`](#signatureimportbuffer-signature---buffer)
- [`.sign(Buffer msg, Buffer secretKey [, Function callback])`](#signbuffer-msg-buffer-secretkey--function-callback---promisebuffer)
- [`.signSync(Buffer msg, Buffer secretKey)`](#signsyncbuffer-msg-buffer-secretkey---buffer)
- [`.verify(Buffer msg, Buffer signature, Buffer publicKey [, Function callback])`](#verifybuffer-msg-buffer-signature-buffer-publickey--function-callback---promiseboolean)
- [`.verifySync(Buffer msg, Buffer signature, Buffer publicKey)`](#verifysyncbuffer-msg-buffer-signature-buffer-publickey---boolean)
- [`.recover(Buffer msg, Buffer signature [, Function callback])`](#recoverbuffer-msg-buffer-signature--function-callback---promisebuffer)
- [`.recoverSync(Buffer msg, Buffer signature)`](#recoversyncbuffer-msg-buffer-signature---buffer)
- [`.ecdh(Buffer secretKey, Buffer publicKey [, Function callback])`](#ecdhbuffer-secretkey-buffer-publickey--function-callback---promisebuffer)
- [`.ecdhSync(Buffer secretKey, Buffer publicKey)`](#ecdhsyncbuffer-secretkey-buffer-publickey---buffer)

#####`.secretKeyVerify(Buffer secretKey)` -> `Boolean`

Verify an ECDSA *secretKey*.

<hr>

#####`.secretKeyExport(Buffer secretKey)` -> `Buffer`

Export a *secretKey* in DER format.

<hr>

#####`.secretKeyImport(Buffer secretKey [, Boolean compressed = true])` -> `Buffer`

Import a *secretKey* in DER format.

<hr>

#####`.secretKeyTweakAdd(Buffer secretKey, Buffer tweak)` -> `Buffer`

Tweak a *secretKey* by adding *tweak* to it.

<hr>

#####`.secretKeyTweakMul(Buffer secretKey, Buffer tweak)` -> `Buffer`

Tweak a *secretKey* by multiplying it by a *tweak*.

<hr>

#####`.publicKeyCreate(Buffer secretKey [, Boolean compressed = true])` -> `Buffer`

Compute the public key for a *secretKey*.

<hr>

#####`.publicKeyConvert(Buffer publicKey [, Boolean compressed = true])` -> `Buffer`

Convert a *publicKey* to *compressed* or *uncompressed* form.

<hr>

#####`.publicKeyVerify(Buffer publicKey)` -> `Boolean`

Verify an ECDSA *publicKey*.

<hr>

#####`.publicKeyTweakAdd(Buffer publicKey, Buffer tweak)` -> `Buffer`

Tweak a *publicKey* by adding *tweak* times the generator to it.

<hr>

#####`.publicKeyTweakMul(Buffer publicKey, Buffer tweak)` -> `Buffer`

Tweak a *publicKey* by multiplying it by a *tweak* value.

<hr>

#####`.signatureNormalize(Buffer signature)` -> `Buffer`

Convert a *signature* to a normalized lower-S form.

<hr>

#####`.signatureExport(Buffer signature)` -> `Buffer`

Serialize an ECDSA *signature* in DER format.

<hr>

#####`.signatureImport(Buffer signature)` -> `Buffer`

Parse a DER ECDSA *signature*.

<hr>

#####`.sign(Buffer msg, Buffer secretKey [, Function callback])` -> `Promise<Buffer>`

Create an ECDSA signature.

<hr>

#####`.signSync(Buffer msg, Buffer secretKey)` -> `Buffer`

Synchronous [.sign](#signbuffer-msg-buffer-secretkey--function-callback---promisebuffer). Returns an instance of `Buffer`. 

<hr>

#####`.verify(Buffer msg, Buffer signature, Buffer publicKey [, Function callback])` -> `Promise<Boolean>`

Verify an ECDSA signature.

<hr>

#####`.verifySync(Buffer msg, Buffer signature, Buffer publicKey` -> `Boolean`

Synchronous [.verify](#verifybuffer-msg-buffer-signature-buffer-publickey--function-callback---promiseboolean). Returns a `Boolean`. 

<hr>

#####`.recover(Buffer msg, Buffer signature [, Function callback]` -> `Promise<Buffer>`

Recover an ECDSA public key from a signature.

<hr>

#####`.recoverSync(Buffer msg, Buffer signature)` -> `Buffer`

Synchronous [.recover](#recoverbuffer-msg-buffer-signature--function-callback---promisebuffer). Returns an instance of `Buffer`. 

<hr>

#####`.ecdh(Buffer secretKey, Buffer publicKey [, Function callback])` -> `Promise<Buffer>`

Compute an EC Diffie-Hellman secret.

<hr>

#####`.ecdhSync(Buffer secretKey, Buffer publicKey)` -> `Buffer`

Synchronous [.ecdh](#ecdhbuffer-secretkey-buffer-publickey--function-callback---promisebuffer). Returns an instance of `Buffer`. 
