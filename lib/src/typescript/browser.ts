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
 * Browser ecies-geth implementation.
 * This is based off the `eccrypto` JS module.
 */
import { ec as EC } from 'elliptic'

// IE 11
declare global {
  interface Window {
    msCrypto?: Crypto
  }
  interface Crypto {
    webkitSubtle?: SubtleCrypto
  }
}

/* eslint-disable @typescript-eslint/unbound-method */

const ec = new EC('secp256k1')
/* eslint-disable @typescript-eslint/strict-boolean-expressions */
const crypto = window.crypto || window.msCrypto! // eslint-disable-line @typescript-eslint/no-non-null-assertion
const subtle: SubtleCrypto = (crypto.subtle || crypto.webkitSubtle)! // eslint-disable-line @typescript-eslint/no-non-null-assertion
/* eslint-enable @typescript-eslint/strict-boolean-expressions */

if (subtle === undefined || crypto === undefined) {
  throw new Error('crypto and/or subtle api unavailable')
}

// Use the browser RNG
const randomBytes = (size: number): Buffer =>
  crypto.getRandomValues(Buffer.alloc(size))

// Get the browser SHA256 implementation
const sha256 = (msg: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer): Promise<Buffer> =>
  subtle.digest({ name: 'SHA-256' }, msg).then(Buffer.from)

// The KDF as implemented in Parity mimics Geth's implementation
export const kdf = (secret: Buffer, outputLength: number): Promise<Buffer> => {
  let ctr = 1
  let written = 0
  let willBeResult = Promise.resolve(Buffer.from(''))
  while (written < outputLength) { // eslint-disable-line no-loops/no-loops
    const ctrs = Buffer.from([ctr >> 24, ctr >> 16, ctr >> 8, ctr])
    const willBeHashResult = sha256(Buffer.concat([ctrs, secret]))
    willBeResult = willBeResult.then(result => willBeHashResult.then(hashResult =>
      Buffer.concat([result, hashResult])
    ))
    written += 32
    ctr += 1
  }
  return willBeResult
}

const aesCtrEncrypt = (
  counter: Buffer,
  key: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer,
  data: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer
): Promise<Buffer> =>
  subtle
    .importKey('raw', key, 'AES-CTR', false, ['encrypt'])
    .then(cryptoKey =>
      subtle.encrypt({ name: 'AES-CTR', counter: counter, length: 128 }, cryptoKey, data)
    ).then(Buffer.from)

const aesCtrDecrypt = (
  counter: Buffer,
  key: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer,
  data: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer
): Promise<Buffer> =>
  subtle
    .importKey('raw', key, 'AES-CTR', false, ['decrypt'])
    .then(cryptoKey =>
      subtle.decrypt({ name: 'AES-CTR', counter: counter, length: 128 }, cryptoKey, data)
    ).then(Buffer.from)

const hmacSha256Sign = (
  key: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer,
  msg: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer
): PromiseLike<Buffer> => {
  const algorithm = { name: 'HMAC', hash: { name: 'SHA-256' } }
  return subtle.importKey('raw', key, algorithm, false, ['sign'])
    .then(cryptoKey => subtle.sign(algorithm, cryptoKey, msg))
    .then(Buffer.from)
}

const hmacSha256Verify = (
  key: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer,
  msg: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer,
  sig: Int8Array | Int16Array | Int32Array | Uint8Array | Uint16Array | Uint32Array | Uint8ClampedArray | Float32Array | Float64Array | DataView | ArrayBuffer
): Promise<boolean> => {
  const algorithm = { name: 'HMAC', hash: { name: 'SHA-256' } }
  const keyp = subtle.importKey('raw', key, algorithm, false, ['verify'])
  return keyp.then(cryptoKey => subtle.verify(algorithm, cryptoKey, sig, msg))
}

/**
 * Compute the public key for a given private key.
 * 
 * @param {Buffer} privateKey - A 32-byte private key
 * @return {Promise<Buffer>} A promise that resolve with the 65-byte public key or reject on wrong private key.
 * @function
 */
export const getPublic = (privateKey: Buffer): Promise<Buffer> => new Promise((resolve, reject) => {
  if (privateKey.length !== 32) {
    reject(new Error('Private key should be 32 bytes long'))
  } else {
    resolve(Buffer.from(ec.keyFromPrivate(privateKey).getPublic('array')))
  }
})

/**
 * Create an ECDSA signature.
 * 
 * @param {Buffer} privateKey - A 32-byte private key
 * @param {Buffer} msg - The message being signed, no more than 32 bytes
 * @return {Promise.<Buffer>} A promise that resolves with the signature and rejects on bad key or message
 */
export const sign = (privateKey: Buffer, msg: Buffer): Promise<Buffer> => new Promise((resolve, reject) => {
  if (privateKey.length !== 32) {
    reject(new Error('Private key should be 32 bytes long'))
  } else if (msg.length <= 0) {
    reject(new Error('Message should not be empty'))
  } else if (msg.length > 32) {
    reject(new Error('Message is too long (max 32 bytes)'))
  } else {
    resolve(Buffer.from(ec.sign(msg, privateKey, { canonical: true }).toDER('hex'), 'hex')) // eslint-disable-line @typescript-eslint/no-unsafe-argument
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
  try {
    if (publicKey.length !== 65 || publicKey[0] !== 4) {
      reject(new Error('Public key should 65 bytes long'))
    } else if (msg.length <= 0) {
      reject(new Error('Message should not be empty'))
    } else if (msg.length > 32) {
      reject(new Error('Message is too long (max 32 bytes)'))
    } else if (!ec.verify(msg, sig.toString('hex') as any, publicKey, 'hex')) { // eslint-disable-line @typescript-eslint/no-unsafe-argument
      reject(new Error('Bad signature'))
    } else {
      resolve(true)
    }
  } catch (e) {
    reject(new Error('Invalid arguments'))
  }
})

/**
 * Derive shared secret for given private and public keys.
 * 
 * @param {Buffer} privateKey - Sender's private key (32 bytes)
 * @param {Buffer} publicKey - Recipient's public key (65 bytes)
 * @return {Promise.<Buffer>} A promise that resolves with the derived shared secret (Px, 32 bytes) and rejects on bad key
 */
export const derive = (privateKeyA: Buffer, publicKeyB: Buffer): Promise<Buffer> => new Promise((resolve, reject) => {
  if (privateKeyA.length !== 32) {
    reject(new Error(`Bad private key, it should be 32 bytes but it's actually ${privateKeyA.length} bytes long`))
  } else if (publicKeyB.length !== 65) {
    reject(new Error(`Bad public key, it should be 65 bytes but it's actually ${publicKeyB.length} bytes long`))
  } else if (publicKeyB[0] !== 4) {
    reject(new Error('Bad public key, a valid public key would begin with 4'))
  } else {
    const keyA = ec.keyFromPrivate(privateKeyA)
    const keyB = ec.keyFromPublic(publicKeyB)
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
  /* eslint-disable @typescript-eslint/strict-boolean-expressions */
  opts = opts || {}
  const ephemPrivateKey = opts.ephemPrivateKey || randomBytes(32)
  return derive(ephemPrivateKey, publicKeyTo)
    .then(sharedPx => kdf(sharedPx, 32))
    .then(async hash => {
      const iv = opts!.iv || randomBytes(16) // eslint-disable-line @typescript-eslint/no-non-null-assertion
      const encryptionKey = hash.slice(0, 16)
      return aesCtrEncrypt(iv, encryptionKey, msg)
        .then(cipherText => Buffer.concat([iv, cipherText]))
        .then(ivCipherText =>
          sha256(hash.slice(16))
            .then(macKey => hmacSha256Sign(macKey, ivCipherText))
            .then(HMAC =>
              getPublic(ephemPrivateKey)
                .then(ephemPublicKey => Buffer.concat([ephemPublicKey, ivCipherText, HMAC]))
            )
        )
    })
  /* eslint-enable @typescript-eslint/strict-boolean-expressions */
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
  if (encrypted.length <= metaLength) {
    reject(new Error(`Invalid Ciphertext. Data is too small. It should ba at least ${metaLength} bytes`))
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
      .then(px => kdf(px, 32))
      .then(hash => sha256(hash.slice(16)).then(macKey => [hash.slice(0, 16), macKey]))
      .then(([encryptionKey, macKey]) =>
        hmacSha256Verify(macKey, cipherAndIv, msgMac)
          .then(isHmacGood => !isHmacGood
            ? Promise.reject(new Error('Incorrect MAC'))
            : aesCtrDecrypt(iv, encryptionKey, ciphertext)
          )
      ).then(Buffer.from))
  }
})

const pad32 = (msg: Buffer): Buffer => {
  if (msg.length < 32) {
    const buff = Buffer.alloc(32).fill(0)
    msg.copy(buff, 32 - msg.length)
    return buff
  } else return msg
}

export * from './model'

/* eslint-enable @typescript-eslint/unbound-method */