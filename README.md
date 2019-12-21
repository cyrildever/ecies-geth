# ecies-geth

This is a JavaScript Elliptic Curve Integrated Encryption Scheme (ECIES) library for use in both Browser and NodeJS apps.
This module is a modified version of the [`eccrypto`](https://github.com/bitchan/eccrypto) JavaScript library.
It's also based off Geth's implementation for Go.

### Motivation

Edgewhere needed to have a JavaScript library fully compliant with the way the Go Ethereum ECIES module ([`ecies`](https://godoc.org/github.com/ethereum/go-ethereum/crypto/ecies)) was implemented.
[Parity](https://www.parity.io/) has implemented ECIES encryption and decryption for arbitrary messages through its extended [JSON RPC API](https://wiki.parity.io/JSONRPC-parity-module.html) and has started translating it into a JavaScript library ([`ecies-parity`](https://www.npmjs.com/package/ecies-parity)). But issues remain in the latter and needed a pass to correct them.


### Implementation details

As with `eccrypto`, this library provides two implementations for Browser and NodeJS with the same API. 

The ECIES implementation details mimic those introduced used by both Geth and Parity, which are:
* Implements a SHA-256 Key Derivation Function (KDF);
* ECDH based only on the `secp256k1` curve (to match common blockchain transaction signing);
* Uses AES-128-CTR based symmetric encryption (with a 128-bit shared key derived from ECDH).

#### Cryptography Warning

The ECIES implementation given here is solely based off Geth's and Parity's implementations. This module offers no guarantee as to the security or validity of the implementation. Furthermore, this project is being actively developed and as such should not be used for highly sensitive informations.  


### Usage

Although this module is primarily developed for ECIES encryption/decryption, extra elliptic curve functionality is provided.

#### ECIES Encryption / Decryption

```typescript
const crypto = require("crypto")
const ecies = require("ecies-geth")

var privateKeyA = crypto.randomBytes(32)
var publicKeyA = ecies.getPublic(privateKeyA)
var privateKeyB = crypto.randomBytes(32)
var publicKeyB = ecies.getPublic(privateKeyB)

// Encrypting the message for B.
ecies.encrypt(publicKeyB, Buffer.from("msg to b")).then(function(encrypted) {
  // B decrypting the message.
  ecies.decrypt(privateKeyB, encrypted).then(function(plaintext) {
    console.log("Message to part B:", plaintext.toString())
  });
});

// Encrypting the message for A.
ecies.encrypt(publicKeyA, Buffer.from("msg to a")).then(function(encrypted) {
  // A decrypting the message.
  ecies.decrypt(privateKeyA, encrypted).then(function(plaintext) {
    console.log("Message to part A:", plaintext.toString())
  });
});
```

#### Signing 

```typescript
const crypto = require("crypto")
const ecies = require("ecies-geth")

// A new random 32-byte private key.
var privateKey = crypto.randomBytes(32)
// Corresponding uncompressed (65-byte) public key.
var publicKey = ecies.getPublic(privateKey)

var str = "message to sign";
// Always hash your message to sign!
var msg = crypto.createHash("sha256").update(str).digest()

ecies.sign(privateKey, msg).then(function(sig) {
  console.log("Signature in DER format:", sig)
  ecies.verify(publicKey, msg, sig).then(function() {
    console.log("Signature is OK")
  }).catch(function() {
    console.log("Signature is BAD")
  })
})
```

#### ECDH

```typescript
const crypto = require("crypto")
const ecies = require("ecies-geth")

var privateKeyA = crypto.randomBytes(32)
var publicKeyA = ecies.getPublic(privateKeyA)
var privateKeyB = crypto.randomBytes(32)
var publicKeyB = ecies.getPublic(privateKeyB)

ecies.derive(privateKeyA, publicKeyB).then(function(sharedKey1) {
  ecies.derive(privateKeyB, publicKeyA).then(function(sharedKey2) {
    console.log("Both shared keys are equal:", sharedKey1, sharedKey2);
  })
})
```


### License

This module is distributed under an MIT license.
See the [LICENSE](LICENSE) file.


<hr />
&copy; 2019-2020 Edgewhere SAS. All rights reserved.