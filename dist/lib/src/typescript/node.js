"use strict";
/*
MIT License

Copyright (c) 2019 Edgewhere

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (Object.hasOwnProperty.call(mod, k)) result[k] = mod[k];
    result["default"] = mod;
    return result;
};
exports.__esModule = true;
/**
 * Note: This module is based off the original eccrypto module.
 */
var crypto_1 = require("crypto");
var secp256k1 = __importStar(require("secp256k1"));
var elliptic_1 = require("elliptic");
var ec = new elliptic_1.ec('secp256k1');
var sha256 = function (msg) {
    return crypto_1.createHash("sha256").update(msg).digest();
};
var hmacSha256 = function (key, msg) {
    return crypto_1.createHmac("sha256", key).update(msg).digest();
};
var aes128CtrEncrypt = function (iv, key, plaintext) {
    var cipher = crypto_1.createCipheriv("aes-128-ctr", key, iv);
    var firstChunk = cipher.update(plaintext);
    var secondChunk = cipher.final();
    return Buffer.concat([iv, firstChunk, secondChunk]);
};
var aes128CtrDecrypt = function (iv, key, ciphertext) {
    var cipher = crypto_1.createDecipheriv("aes-128-ctr", key, iv);
    var firstChunk = cipher.update(ciphertext);
    var secondChunk = cipher.final();
    return Buffer.concat([firstChunk, secondChunk]);
};
// Compare two buffers in constant time to prevent timing attacks
var equalConstTime = function (b1, b2) {
    if (b1.length !== b2.length) {
        return false;
    }
    var res = 0;
    for (var i = 0; i < b1.length; i++) {
        res |= b1[i] ^ b2[i];
    }
    return res === 0;
};
var pad32 = function (msg) {
    if (msg.length < 32) {
        var buff = Buffer.alloc(32).fill(0);
        msg.copy(buff, 32 - msg.length);
        return buff;
    }
    else
        return msg;
};
// The KDF as implemented in Parity mimics Geth's implementation
exports.kdf = function (secret, outputLength) {
    var ctr = 1;
    var written = 0;
    var result = Buffer.from('');
    while (written < outputLength) {
        var ctrs = Buffer.from([ctr >> 24, ctr >> 16, ctr >> 8, ctr]);
        var hashResult = sha256(Buffer.concat([ctrs, secret]));
        result = Buffer.concat([result, hashResult]);
        written += 32;
        ctr += 1;
    }
    return result;
};
/**
 * Compute the public key for a given private key.
 *
 * @param {Buffer} privateKey - A 32-byte private key
 * @return {Promise<Buffer>} A promise that resolve with the 65-byte public key or reject on wrong private key.
 * @function
 */
exports.getPublic = function (privateKey) { return new Promise(function (resolve, reject) {
    return privateKey.length !== 32
        ? reject(new Error('Private key should be 32 bytes long'))
        : resolve(secp256k1.publicKeyConvert(secp256k1.publicKeyCreate(privateKey), false));
} // See https://github.com/wanderer/secp256k1-node/issues/46
); };
/**
 * Create an ECDSA signature.
 *
 * @param {Buffer} privateKey - A 32-byte private key
 * @param {Buffer} msg - The message being signed, no more than 32 bytes
 * @return {Promise.<Buffer>} A promise that resolves with the signature and rejects on bad key or message.
 */
exports.sign = function (privateKey, msg) {
    return new Promise(function (resolve, reject) {
        if (privateKey.length !== 32)
            reject(new Error('Private key should be 32 bytes long'));
        else if (msg.length <= 0)
            reject(new Error('Message should not be empty'));
        else if (msg.length >= 32)
            reject(new Error('Message is too long (max 32 bytes)'));
        else {
            var padded = pad32(msg);
            var signed = secp256k1.sign(padded, privateKey).signature;
            resolve(secp256k1.signatureExport(signed));
        }
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
        if (publicKey.length !== 65)
            reject(new Error('Public key should 65 bytes long'));
        else if (msg.length <= 0)
            reject(new Error('Message should not be empty'));
        else if (msg.length >= 32)
            reject(new Error('Message is too long (max 32 bytes)'));
        else {
            var passed = pad32(msg);
            var signed = secp256k1.signatureImport(sig);
            if (secp256k1.verify(passed, signed, publicKey)) {
                resolve(null);
            }
            else {
                reject(new Error('Bad signature'));
            }
        }
    });
};
/**
 * Derive shared secret for given private and public keys.
 *
 * @param {Buffer} privateKey - Sender's private key (32 bytes)
 * @param {Buffer} publicKey - Recipient's public key (65 bytes)
 * @return {Promise.<Buffer>} A promise that resolves with the derived shared secret (Px, 32 bytes) and rejects on bad key
 */
exports.derive = function (privateKey, publicKey) {
    return new Promise(function (resolve, reject) {
        if (privateKey.length !== 32)
            reject(new Error("Bad private key, it should be 32 bytes but it's actualy " + privateKey.length + " bytes long"));
        else if (publicKey.length !== 65)
            reject(new Error("Bad public key, it should be 65 bytes but it's actualy " + publicKey.length + " bytes long"));
        else if (publicKey[0] !== 4)
            reject(new Error("Bad public key, a valid public key would begin with 4"));
        else {
            var keyA = ec.keyFromPrivate(privateKey);
            var keyB = ec.keyFromPublic(publicKey);
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
    var ephemPrivateKey = opts.ephemPrivateKey || crypto_1.randomBytes(32);
    return exports.derive(ephemPrivateKey, publicKeyTo).then(function (sharedPx) {
        var hash = exports.kdf(sharedPx, 32);
        var encryptionKey = hash.slice(0, 16);
        var iv = opts.iv || crypto_1.randomBytes(16);
        var macKey = sha256(hash.slice(16));
        var cipherText = aes128CtrEncrypt(iv, encryptionKey, msg);
        var HMAC = hmacSha256(macKey, cipherText);
        return exports.getPublic(ephemPrivateKey).then(function (ephemPublicKey) {
            return Buffer.concat([ephemPublicKey, cipherText, HMAC]);
        });
    });
};
var metaLength = 1 + 64 + 16 + 32;
/**
 * Decrypt message using given private key.
 *
 * @param {Buffer} privateKey - A 32-byte private key of recepient of the message
 * @param {Ecies} encrypted - ECIES serialized structure (result of ECIES encryption)
 * @return {Promise.<Buffer>} - A promise that resolves with the plaintext on successful decryption and rejects on failure
 */
exports.decrypt = function (privateKey, encrypted) { return new Promise(function (resolve, reject) {
    if (encrypted.length < metaLength)
        reject(new Error("Invalid Ciphertext. Data is too small. It should ba at least " + metaLength));
    else if (encrypted[0] !== 4)
        reject(new Error('Not valid ciphertext. A valid ciphertext would begin with 4'));
    else {
        // deserialise
        var ephemPublicKey = encrypted.slice(0, 65);
        var cipherTextLength = encrypted.length - metaLength;
        var iv_1 = encrypted.slice(65, 65 + 16);
        var cipherAndIv_1 = encrypted.slice(65, 65 + 16 + cipherTextLength);
        var ciphertext_1 = cipherAndIv_1.slice(16);
        var msgMac_1 = encrypted.slice(65 + 16 + cipherTextLength);
        // check HMAC
        resolve(exports.derive(privateKey, ephemPublicKey).then(function (sharedPx) {
            var hash = exports.kdf(sharedPx, 32);
            var encryptionKey = hash.slice(0, 16);
            var macKey = sha256(hash.slice(16));
            var currentHMAC = hmacSha256(macKey, cipherAndIv_1);
            if (!equalConstTime(currentHMAC, msgMac_1))
                return Promise.reject(new Error('Incorrect MAC'));
            // decrypt message
            var plainText = aes128CtrDecrypt(iv_1, encryptionKey, ciphertext_1);
            return Buffer.from(new Uint8Array(plainText));
        }));
    }
}); };
