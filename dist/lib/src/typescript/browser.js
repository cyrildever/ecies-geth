"use strict";
exports.__esModule = true;
/**
 * Browser ecies-geth implementation.
 * This is based off the eccrypto js module.
 */
var elliptic_1 = require("elliptic");
var ec = new elliptic_1.ec('secp256k1');
var crypto = window.crypto || window.msCrypto;
var subtle = (crypto.subtle || crypto.webkitSubtle);
if (subtle === undefined || crypto === undefined) //TODO maybe better ?
    //throw new Error('crypto and/or subtle api unavailable')
    console.error('crypto and/or subtle api unavailable');
// Use the browser RNG
var randomBytes = function (size) {
    return crypto.getRandomValues(Buffer.alloc(size));
};
// Get the browser SHA256 implementation
var sha256 = function (msg) {
    return subtle.digest({ name: "SHA-256" }, msg).then(Buffer.from);
};
// The KDF as implemented in Parity mimics Geth's implementation
exports.kdf = function (secret, outputLength) {
    var ctr = 1;
    var written = 0;
    var willBeResult = Promise.resolve(Buffer.from(''));
    var _loop_1 = function () {
        var ctrs = Buffer.from([ctr >> 24, ctr >> 16, ctr >> 8, ctr]);
        var willBeHashResult = sha256(Buffer.concat([ctrs, secret]));
        willBeResult = willBeResult.then(function (result) { return willBeHashResult.then(function (hashResult) {
            return Buffer.concat([result, hashResult]);
        }); });
        written += 32;
        ctr += 1;
    };
    while (written < outputLength) {
        _loop_1();
    }
    return willBeResult;
};
// Get the AES-128-CTR browser implementation
var getAes = function (op) { return function (counter, key, data) {
    return subtle
        .importKey("raw", key, "AES-CTR", false, [op.name])
        .then(function (cryptoKey) {
        return op({ name: "AES-CTR", counter: counter, length: 128 }, cryptoKey, data);
    }).then(Buffer.from);
}; };
var aesCtrEncrypt = getAes(subtle.encrypt);
var aesCtrDecrypt = getAes(subtle.decrypt);
var hmacSha256Sign = function (key, msg) {
    var algorithm = { name: "HMAC", hash: { name: "SHA-256" } };
    return subtle.importKey("raw", key, algorithm, false, ["sign"])
        .then(function (cryptoKey) { return subtle.sign(algorithm, cryptoKey, msg); })
        .then(Buffer.from);
};
var hmacSha256Verify = function (key, msg, sig) {
    var algorithm = { name: "HMAC", hash: { name: "SHA-256" } };
    var keyp = subtle.importKey("raw", key, algorithm, false, ["verify"]);
    return keyp.then(function (cryptoKey) { return subtle.verify(algorithm, cryptoKey, sig, msg); });
};
/**
 * Compute the public key for a given private key.
 *
 * @param {Buffer} privateKey - A 32-byte private key
 * @return {Promise<Buffer>} A promise that resolve with the 65-byte public key or reject on wrong private key.
 * @function
 */
exports.getPublic = function (privateKey) { return new Promise(function (resolve, reject) {
    if (privateKey.length !== 32)
        reject(new Error('Bad private key'));
    else
        resolve(Buffer.from(ec.keyFromPrivate(privateKey).getPublic('array')));
}); };
/**
 * Create an ECDSA signature.
 *
 * @param {Buffer} privateKey - A 32-byte private key
 * @param {Buffer} msg - The message being signed, no more than 32 bytes
 * @return {Promise.<Buffer>} A promise that resolves with the signature and rejects on bad key or message
 */
exports.sign = function (privateKey, msg) {
    return new Promise(function (resolve, reject) {
        if (privateKey.length !== 32)
            reject(new Error('Bad private key'));
        else if (msg.length <= 0)
            reject(new Error('Message should not be empty'));
        else if (msg.length > 32)
            reject(new Error('Message is too long'));
        else
            resolve(Buffer.from(ec.sign(msg, privateKey, { canonical: true }).toDER('hex'), 'hex'));
    });
};
/**
 * Verify an ECDSA signature.
 *
 * @param {Buffer} publicKey - A 65-byte public key
 * @param {Buffer} msg - The message being verified
 * @param {Buffer} sig - The signature
 * @return {Promise.<null>} A promise that resolves on correct signature and rejects on bad key or signature
 */
exports.verify = function (publicKey, msg, sig) {
    return new Promise(function (resolve, reject) {
        if (publicKey.length !== 65 || publicKey[0] !== 4)
            reject(new Error('Bad public key'));
        else if (msg.length <= 0)
            reject(new Error('Message should not be empty'));
        else if (msg.length > 32)
            reject(new Error('Message is too long'));
        else if (!ec.verify(msg, sig.toString('hex'), publicKey, 'hex'))
            reject(new Error("Bad signature"));
        else
            resolve(null);
    });
};
/**
 * Derive shared secret for given private and public keys.
 *
 * @param {Buffer} privateKey - Sender's private key (32 bytes)
 * @param {Buffer} publicKey - Recipient's public key (65 bytes)
 * @return {Promise.<Buffer>} A promise that resolves with the derived shared secret (Px, 32 bytes) and rejects on bad key
 */
exports.derive = function (privateKeyA, publicKeyB) {
    return new Promise(function (resolve, reject) {
        if (privateKeyA.length !== 32)
            reject(new Error("Bad private key, it should be 32 bytes but it's actualy " + privateKeyA.length + " bytes long"));
        else if (publicKeyB.length !== 65)
            reject(new Error("Bad public key, it should be 65 bytes but it's actualy " + publicKeyB.length + " bytes long"));
        else if (publicKeyB[0] !== 4)
            reject(new Error("Bad public key, a valid public key would begin with 4"));
        else {
            var keyA = ec.keyFromPrivate(privateKeyA);
            var keyB = ec.keyFromPublic(publicKeyB);
            var Px = keyA.derive(keyB.getPublic()); // BN instance
            resolve(Buffer.from(Px.toArray()));
        }
    });
};
/**
 * Encrypt message for given recepient's public key.
 *
 * @param {Buffer} publicKeyTo - Recipient's public key (65 bytes)
 * @param {Buffer} msg - The message being encrypted
 * @param {?{?iv: Buffer, ?ephemPrivateKey: Buffer}} opts - You may also specify initialization vector (16 bytes) and ephemeral private key (32 bytes) to get deterministic results.
 * @return {Promise.<Buffer>} - A promise that resolves with the ECIES structure serialized
 */
exports.encrypt = function (publicKeyTo, msg, opts) {
    opts = opts || {};
    var ephemPrivateKey = opts.ephemPrivateKey || randomBytes(32);
    var willBeSharedPx = exports.derive(ephemPrivateKey, publicKeyTo);
    var willBeHash = willBeSharedPx.then(function (sharedPx) { return exports.kdf(sharedPx, 32); });
    var iv = opts.iv || randomBytes(16);
    var willBeEncryptionKey = willBeHash.then(function (hash) { return hash.slice(0, 16); });
    var willBeMacKey = willBeHash.then(function (hash) { return sha256(hash.slice(16)); });
    var willBeCipherText = willBeEncryptionKey.then(function (encryptionKey) { return aesCtrEncrypt(iv, encryptionKey, msg); });
    var willBeIvCipherText = willBeCipherText.then(function (cipherText) { return Buffer.concat([iv, cipherText]); });
    var willBeHMAC = willBeMacKey.then(function (macKey) { return willBeIvCipherText.then(function (ivCipherText) { return hmacSha256Sign(macKey, ivCipherText); }); });
    var willBeEphemPublicKey = exports.getPublic(ephemPrivateKey);
    return willBeEphemPublicKey.then(function (ephemPublicKey) { return willBeIvCipherText.then(function (ivCipherText) { return willBeHMAC.then(function (HMAC) {
        return Buffer.concat([ephemPublicKey, ivCipherText, HMAC]);
    }); }); });
};
var metaLength = 1 + 64 + 16 + 32;
/**
 * Decrypt message using given private key.
 *
 * @param {Buffer} privateKey - A 32-byte private key of recepient of the message
 * @param {Ecies} encrypted - ECIES serialized structure (result of ECIES encryption)
 * @return {Promise.<Buffer>} - A promise that resolves with the plaintext on successful decryption and rejects on failure
 */
exports.decrypt = function (privateKey, encrypted) {
    return new Promise(function (resolve, reject) {
        if (encrypted.length <= metaLength)
            reject(new Error("Invalid Ciphertext. Data is too small, should be more than " + metaLength + " bytes"));
        else if (encrypted[0] < 2 && encrypted[0] > 4)
            reject(new Error("Not a valid ciphertext. It should begin with 2, 3 or 4 but actualy begin with " + encrypted[0]));
        else {
            // deserialise
            var ephemPublicKey = encrypted.slice(0, 65);
            var cipherTextLength = encrypted.length - metaLength;
            var iv_1 = encrypted.slice(65, 65 + 16);
            var cipherAndIv_1 = encrypted.slice(65, 65 + 16 + cipherTextLength);
            var ciphertext_1 = cipherAndIv_1.slice(16);
            var msgMac_1 = encrypted.slice(65 + 16 + cipherTextLength);
            // check HMAC
            var willBePx = exports.derive(privateKey, ephemPublicKey);
            var willBeHash = willBePx.then(function (px) { return exports.kdf(px, 32); });
            var willBeEncryptionKey_1 = willBeHash.then(function (hash) { return hash.slice(0, 16); });
            var willBeMacKey = willBeHash.then(function (hash) { return sha256(hash.slice(16)); });
            willBeMacKey.then(function (macKey) { return hmacSha256Verify(macKey, cipherAndIv_1, msgMac_1); })
                .then(function (isHmacGood) { return willBeEncryptionKey_1.then(function (encryptionKey) {
                if (!isHmacGood)
                    reject(new Error('Incorrect MAC'));
                else {
                    // decrypt message
                    aesCtrDecrypt(iv_1, encryptionKey, ciphertext_1).then(function (plainText) {
                        return resolve(Buffer.from(plainText));
                    });
                }
            }); })["catch"](reject);
        }
    });
};
