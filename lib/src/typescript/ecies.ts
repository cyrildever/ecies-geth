/*
MIT License

Copyright (c) 2019 Cyril Dever

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

/**
 * Note: This module is based off the original eccrypto module.
 */

// import { createHash, BinaryLike, createCipheriv, createDecipheriv, createHmac, randomBytes } from 'crypto'
import { ec as EC } from 'elliptic'
import secp256k1 from 'secp256k1'

const ec = new EC('secp256k1')
let cryptoModule: any
if (typeof window === 'undefined') {
  // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-require-imports
  cryptoModule = require('crypto')
}

const sha256 = (msg: any): any => {
  /* eslint-disable */
  if (typeof window !== 'undefined') {
    const browserCrypto = window.crypto || window.msCrypto!
    const subtle: SubtleCrypto = browserCrypto.subtle || browserCrypto.webkitSubtle
    return subtle.digest({ name: 'SHA-256' }, msg).then(Buffer.from)
  } else if (cryptoModule) {
    /*  */
    return cryptoModule.createHash('sha256').update(msg).digest()
  } else {
    throw Error('missing mandatory crypto modules')
  }
  /* eslint-enable */
}

const hmacSha256 = (key: BinaryLike, msg: BinaryLike): Buffer =>
  createHmac('sha256', key).update(msg).digest()

const aes128CtrEncrypt = (iv: Buffer, key: Buffer, plaintext: Buffer): Buffer => {
  const cipher = createCipheriv('aes-128-ctr', key, iv)
  const firstChunk = cipher.update(plaintext)
  const secondChunk = cipher.final()
  return Buffer.concat([iv, firstChunk, secondChunk])
}

const aes128CtrDecrypt = (iv: Buffer, key: Buffer, ciphertext: Buffer): Buffer => {
  const cipher = createDecipheriv('aes-128-ctr', key, iv)
  const firstChunk = cipher.update(ciphertext)
  const secondChunk = cipher.final()
  return Buffer.concat([firstChunk, secondChunk])
}

// Compare two buffers in constant time to prevent timing attacks
const equalConstTime = (b1: Buffer, b2: Buffer): boolean => {
  if (b1.length !== b2.length) {
    return false
  }
  let res = 0
  for (let i = 0; i < b1.length; i++) { // eslint-disable-line no-loops/no-loops
    res |= b1[i] ^ b2[i]
  }
  return res === 0
}

const pad32 = (msg: Buffer): Buffer => {
  if (msg.length < 32) {
    const buff = Buffer.alloc(32).fill(0)
    msg.copy(buff, 32 - msg.length)
    return buff
  } else return msg
}

// The KDF as implemented in Parity mimics Geth's implementation
export const kdf = (secret: Buffer, outputLength: number): Promise<Buffer> => new Promise(resolve => {
  let ctr = 1
  let written = 0
  let result = Buffer.from('')
  while (written < outputLength) { // eslint-disable-line no-loops/no-loops
    const ctrs = Buffer.from([ctr >> 24, ctr >> 16, ctr >> 8, ctr])
    const hashResult = sha256(Buffer.concat([ctrs, secret]))
    result = Buffer.concat([result, hashResult])
    written += 32
    ctr += 1
  }
  resolve(result)
})

/**
 * Compute the public key for a given private key.
 * 
 * @param {Buffer} privateKey - A 32-byte private key
 * @return {Promise<Buffer>} A promise that resolve with the 65-byte public key or reject on wrong private key.
 * @function
 */
export const getPublic = (privateKey: Buffer): Promise<Buffer> => new Promise((resolve, reject) =>
  privateKey.length !== 32
    ? reject(new Error('Private key should be 32 bytes long'))
    : resolve(Buffer.from(secp256k1.publicKeyConvert(secp256k1.publicKeyCreate(privateKey), false))) // See https://github.com/wanderer/secp256k1-node/issues/46
)

/**
 * Create an ECDSA signature.
 * 
 * @param {Buffer} privateKey - A 32-byte private key
 * @param {Buffer} msg - The message being signed, no more than 32 bytes
 * @return {Promise.<Buffer>} A promise that resolves with the signature and rejects on bad key or message.
 */
export const sign = (privateKey: Buffer, msg: Buffer): Promise<Buffer> => new Promise((resolve, reject) => {
  if (privateKey.length !== 32) {
    reject(new Error('Private key should be 32 bytes long'))
  } else if (msg.length <= 0) {
    reject(new Error('Message should not be empty'))
  } else if (msg.length > 32) {
    reject(new Error('Message is too long (max 32 bytes)'))
  } else {
    const padded = pad32(msg)
    const signed = secp256k1.ecdsaSign(padded, privateKey).signature
    resolve(Buffer.from(secp256k1.signatureExport(signed)))
  }
})

/**
 * Verify an ECDSA signature.
 * 
 * @param {Buffer} publicKey - A 65-byte public key
 * @param {Buffer} msg - The message being verified
 * @param {Buffer} sig - The signature
 * @return {Promise.<true>} A promise that resolves on correct signature and rejects on bad key or signature
 */
export const verify = (publicKey: Buffer, msg: Buffer, sig: Buffer): Promise<true> => new Promise((resolve, reject) => {
  if (publicKey.length !== 65) {
    reject(new Error('Public key should 65 bytes long'))
  } else if (msg.length <= 0) {
    reject(new Error('Message should not be empty'))
  } else if (msg.length > 32) {
    reject(new Error('Message is too long (max 32 bytes)'))
  } else {
    const passed = pad32(msg)
    try {
      const signed = secp256k1.signatureImport(sig)
      if (secp256k1.ecdsaVerify(signed, passed, publicKey)) {
        resolve(true)
      } else {
        reject(new Error('Bad signature'))
      }
    } catch (_) { // eslint-disable-line @typescript-eslint/no-unused-vars
      reject(new Error('Invalid signature'))
    }
  }
})

/**
 * Derive shared secret for given private and public keys.
 * 
 * @param {Buffer} privateKey - Sender's private key (32 bytes)
 * @param {Buffer} publicKey - Recipient's public key (65 bytes)
 * @return {Promise.<Buffer>} A promise that resolves with the derived shared secret (Px, 32 bytes) and rejects on bad key
 */
export const derive = (privateKey: Buffer, publicKey: Buffer): Promise<Buffer> => new Promise((resolve, reject) => {
  if (privateKey.length !== 32) {
    reject(new Error(`Bad private key, it should be 32 bytes but it's actually ${privateKey.length} bytes long`))
  } else if (publicKey.length !== 65) {
    reject(new Error(`Bad public key, it should be 65 bytes but it's actually ${publicKey.length} bytes long`))
  } else if (publicKey[0] !== 4) {
    reject(new Error('Bad public key, a valid public key would begin with 4'))
  } else {
    const keyA = ec.keyFromPrivate(privateKey)
    const keyB = ec.keyFromPublic(publicKey)
    const Px = keyA.derive(keyB.getPublic()) // BN instance
    resolve(pad32(Buffer.from(Px.toArray())))
  }
})

/**
 * Encrypt message for given recepient's public key.
 * 
 * @param {Buffer} publicKeyTo - Recipient's public key (65 bytes)
 * @param {Buffer} msg - The message being encrypted
 * @param {?{?iv: Buffer, ?ephemPrivateKey: Buffer}} opts - You may also specify initialization vector (16 bytes) and ephemeral private key (32 bytes) to get deterministic results.
 * @return {Promise.<Buffer>} - A promise that resolves with the ECIES structure serialized
 */
export const encrypt = async (publicKeyTo: Buffer, msg: Buffer, opts?: { iv?: Buffer; ephemPrivateKey?: Buffer }): Promise<Buffer> => {

  opts = opts || {}
  const ephemPrivateKey = opts.ephemPrivateKey || randomBytes(32)
  return derive(ephemPrivateKey, publicKeyTo)
    .then(sharedPx => kdf(sharedPx, 32))
    .then(async hash => {
      const encryptionKey = hash.slice(0, 16)
      const iv = opts.iv || randomBytes(16)
      const macKey = sha256(hash.slice(16))
      const cipherText = aes128CtrEncrypt(iv, encryptionKey, msg)
      const HMAC = hmacSha256(macKey, cipherText)
      return getPublic(ephemPrivateKey).then(ephemPublicKey =>
        Buffer.concat([ephemPublicKey, cipherText, HMAC])
      )
    })

}

const metaLength = 1 + 64 + 16 + 32

/**
 * Decrypt message using given private key.
 * 
 * @param {Buffer} privateKey - A 32-byte private key of recepient of the message
 * @param {Ecies} encrypted - ECIES serialized structure (result of ECIES encryption)
 * @return {Promise.<Buffer>} - A promise that resolves with the plaintext on successful decryption and rejects on failure
 */
export const decrypt = (privateKey: Buffer, encrypted: Buffer): Promise<Buffer> => new Promise((resolve, reject) => {
  if (encrypted.length < metaLength) {
    reject(new Error(`Invalid Ciphertext. Data is too small. It should ba at least ${metaLength}`))
  } else if (encrypted[0] !== 4) {
    reject(new Error(`Not a valid ciphertext. It should begin with 4 but actually begin with ${encrypted[0]}`))
  } else {
    // deserialize
    const ephemPublicKey = encrypted.slice(0, 65)
    const cipherTextLength = encrypted.length - metaLength
    const iv = encrypted.slice(65, 65 + 16)
    const cipherAndIv = encrypted.slice(65, 65 + 16 + cipherTextLength)
    const ciphertext = cipherAndIv.slice(16)
    const msgMac = encrypted.slice(65 + 16 + cipherTextLength)

    // check HMAC
    resolve(derive(privateKey, ephemPublicKey)
      .then(sharedPx => kdf(sharedPx, 32))
      .then(hash => {
        const encryptionKey = hash.slice(0, 16)
        const macKey = sha256(hash.slice(16))
        const currentHMAC = hmacSha256(macKey, cipherAndIv)
        if (!equalConstTime(currentHMAC, msgMac)) {
          return Promise.reject(new Error('Incorrect MAC'))
        }
        // decrypt message
        const plainText = aes128CtrDecrypt(iv, encryptionKey, ciphertext)
        return Buffer.from(new Uint8Array(plainText))
      }))
  }
})

export * from './model'
