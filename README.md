# ecies-geth

![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/cyrildever/ecies-geth)
![npm](https://img.shields.io/npm/dw/ecies-geth)
![GitHub last commit](https://img.shields.io/github/last-commit/cyrildever/ecies-geth)
![GitHub issues](https://img.shields.io/github/issues/cyrildever/ecies-geth)
![NPM](https://img.shields.io/npm/l/ecies-geth)

This is a JavaScript Elliptic Curve Integrated Encryption Scheme (ECIES) library for use in both Browser and NodeJS apps.
This module is a modified version of the [`eccrypto`](https://github.com/bitchan/eccrypto) JavaScript library.
It's also based off Geth's implementation (Ethereum's `ecies` Go module).

### Motivation

We needed to have a JavaScript library fully compliant with the way the Go Ethereum ECIES module ([`ecies`](https://godoc.org/github.com/ethereum/go-ethereum/crypto/ecies)) was implemented. \
[Parity](https://www.parity.io/) has implemented ECIES encryption and decryption for arbitrary messages through its extended [JSON RPC API](https://wiki.parity.io/JSONRPC-parity-module.html) and has started translating it into a JavaScript library ([`ecies-parity`](https://www.npmjs.com/package/ecies-parity)). But issues remain in the latter and needed a pass to correct them.


### Implementation details

As with `eccrypto`, this library provides two implementations for Browser and NodeJS with the same API.

The ECIES implementation details mimic those introduced by both Geth and Parity, which are:
* Implements a __SHA-256__ Key Derivation Function (KDF);
* ECDH based only on the `secp256k1` curve (to match common blockchain transaction signing);
* Uses __AES-128-CTR__ based symmetric encryption (with a 128-bit shared key derived from ECDH).

#### _Cryptography Warning_

The ECIES implementation given here is solely based off Geth's and Parity's implementations. This module offers no guarantee as to the security or validity of the implementation. Furthermore, this project is being actively developed and as such should not be used for highly sensitive informations without further investigation on its robustness. Any feedback or concerns regarding its security would be greatly appreciated.


### Usage

```
npm i ecies-geth
```

Although this module was primarily developed for ECIES encryption/decryption, extra elliptic curve functionalities are provided.

#### ECIES Encryption / Decryption

```js
const crypto = require('crypto');
const ecies = require('ecies-geth');

const privateKeyA = crypto.randomBytes(32);
const publicKeyA = await ecies.getPublic(privateKeyA);
const privateKeyB = crypto.randomBytes(32);
const publicKeyB = await ecies.getPublic(privateKeyB);

// Encrypting the message for B.
ecies.encrypt(publicKeyB, Buffer.from('msg to b')).then(function(encrypted) {
  // B decrypting the message.
  ecies.decrypt(privateKeyB, encrypted).then(function(plaintext) {
    console.log('Message to part B', plaintext.toString());
  });
});

// Encrypting the message for A.
ecies.encrypt(publicKeyA, Buffer.from('msg to a')).then(function(encrypted) {
  // A decrypting the message.
  ecies.decrypt(privateKeyA, encrypted).then(function(plaintext) {
    console.log('Message to part A', plaintext.toString());
  });
});
```

#### ECDSA Signing 

```js
const crypto = require('crypto');
const ecies = require('ecies-geth');

// A new random 32-byte private key.
const privateKey = crypto.randomBytes(32)
// Corresponding uncompressed (65-byte) public key.
const publicKey = await ecies.getPublic(privateKey);

const str = 'message to sign';
// Always hash your message to sign!
const msg = crypto.createHash('sha256').update(str).digest();

ecies.sign(privateKey, msg).then(function(sig) {
  console.log('Signature in DER format:', sig);
  ecies.verify(publicKey, msg, sig).then(function() {
    console.log('Signature is OK');
  }).catch(function() {
    console.log('Signature is BAD');
  });
})
```

#### ECDH Derivation

```js
const crypto = require('crypto');
const ecies = require('ecies-geth');

const privateKeyA = crypto.randomBytes(32);
const publicKeyA = await ecies.getPublic(privateKeyA);
const privateKeyB = crypto.randomBytes(32);
const publicKeyB = await ecies.getPublic(privateKeyB);

ecies.derive(privateKeyA, publicKeyB).then(function(sharedKey1) {
  ecies.derive(privateKeyB, publicKeyA).then(function(sharedKey2) {
    console.log('Both shared keys are equal', sharedKey1, sharedKey2);
  })
})
```

### Dependencies

This library relies on the following dependencies:
- [`elliptic`](https://www.npmjs.com/package/elliptic);
- [`secp256k1`](https://www.npmjs.com/package/secp256k1).

To run the tests, you would need to install [`live-server`](https://www.npmjs.com/package/live-server):
```console
npm i -g live-server
```

#### _Security advisory_

`npm audit` currently reports [GHSA-848j-6mx2-7j84](https://github.com/advisories/GHSA-848j-6mx2-7j84) (CVE-2025-14505, `low` severity) against `elliptic`. No patched version exists: the advisory covers every release up to and including `6.6.1`, which is also the latest one ever published, so no `overrides` entry can resolve it. The only fix `npm audit fix --force` knows how to propose is a downgrade to the long-unmaintained `secp256k1@1.1.6`, and it should not be applied. Note that `elliptic` would remain in the dependency tree in any case, since `secp256k1` depends on it.

The actual exposure of this library is limited. The advisory concerns the truncation of the RFC 6979 nonce during __ECDSA signing only__: ECDH derivation is out of its scope. The NodeJS implementation signs through the native `secp256k1` bindings, and therefore only reaches the affected code path when those bindings fail to load and `secp256k1` falls back to its pure-JS `elliptic` backend. The Browser implementation, on the other hand, always signs through `elliptic`.

Both findings being of `low` severity, a CI pipeline can be kept green without resorting to `--force`:
```console
$ npm audit --omit=dev --audit-level=moderate
```


### Credits

Thanks to [@Methrat0n](https://github.com/Methrat0n/) for the initial work on this adaptation.


### License

This module is distributed under a MIT license. \
See the [LICENSE](LICENSE) file.


<hr />
&copy; 2019-2026 Cyril Dever. All rights reserved.