# secp256k1-node

[![NPM Package](https://img.shields.io/npm/v/secp256k1.svg?style=flat-square)](https://www.npmjs.org/package/secp256k1)
[![Build Status](https://img.shields.io/travis/cryptocoinjs/secp256k1-node.svg?branch=master&style=flat-square)](https://travis-ci.org/cryptocoinjs/secp256k1-node)
[![Dependency status](https://img.shields.io/david/cryptocoinjs/secp256k1-node.svg?style=flat-square)](https://david-dm.org/cryptocoinjs/secp256k1-node#info=dependencies)

[![js-standard-style](https://cdn.rawgit.com/feross/standard/master/badge.svg)](https://github.com/feross/standard)

This module provides native bindings to ecdsa [secp256k1](https://github.com/bitcoin/secp256k1) functions.
This library is experimental, so use at your own risk. Works on node version 0.11 or greater and in the Browser via browserify.

# Installation

If you have gmp installed secp256k1 will use it. Otherwise it should fallback to openssl.
* arch `pacman -S gmp`
* ubuntu `sudo apt-get install libgmp-dev`

##### from npm

`npm install secp256k1`

##### from git

```
git clone git@github.com:cryptocoinjs/secp256k1-node.git
cd secp256k1-node
npm install
```

# Usage

* [API Reference (v3.x)](API.md)

```js
var crypto = require('crypto')
var secp256k1 = require('secp256k1')
// or require('secp256k1/js')
//   if you want to use pure js implementation in node

// generate message to sign
var msg = crypto.randomBytes(32)

// generate privKey
var privKey
do {
  privKey = crypto.randomBytes(32)
} while (!secp256k1.privateKeyVerify(privKey))

// get the public key in a compressed format
var pubKey = secp256k1.publicKeyCreate(privKey)

// sign the message
var sigObj = secp256k1.sign(msg, privKey)

// verify the signature
console.log(secp256k1.verify(msg, sigObj.signature, pubKey))
```

# Elliptic vs "embedded"

secp256k1-node has pure JavaScript implementation secp256k1 based on [elliptic](http://github.com/indutny/elliptic), [bn.js](http://github.com/indutny/bn.js), [hash.js](http://github.com/indutny/hash.js).
The main purpose of this implementation is more high performance, smaller size and simple code audit.

##### Code size:
|        | browserifiable | + uglified | + gzipped |
|:------:|:--------------:|:----------:|:---------:|
|elliptic|303555          |211777      |62124      |
|embedded|129498          |88958       |20188      |

##### Performance:
```
$ node benchmark/benchmark.js
Set seed: 3a00dcae78029d625de424ee270cf1fe65a2428f51acbabf19ec8021b5de206c
100% (1000/1000), 2.8s elapsed, eta 0.0s
Create 1000 fixtures
++++++++++++++++++++++++++++++++++++++++++++++++++
Benchmarking: publicKeyCreate
--------------------------------------------------
bindings x 14,035 ops/sec ±0.54% (102 runs sampled)
secp256k1js x 987 ops/sec ±0.36% (101 runs sampled)
elliptic x 840 ops/sec ±0.66% (99 runs sampled)
==================================================
Benchmarking: sign
--------------------------------------------------
bindings x 8,194 ops/sec ±0.17% (103 runs sampled)
secp256k1js x 777 ops/sec ±0.30% (99 runs sampled)
elliptic x 615 ops/sec ±0.37% (97 runs sampled)
==================================================
Benchmarking: verify
--------------------------------------------------
bindings x 5,378 ops/sec ±0.09% (103 runs sampled)
secp256k1js x 209 ops/sec ±0.15% (91 runs sampled)
elliptic x 115 ops/sec ±21.85% (86 runs sampled)
==================================================
```

# LICENSE

This library is free and open-source software released under the MIT license.
