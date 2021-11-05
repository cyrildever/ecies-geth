import chaiAsPromised from 'chai-as-promised'

type ECIES = typeof import('../../..') // only import types from the node
const ecies = require('../../../lib/src/typescript/index') as ECIES // eslint-disable-line @typescript-eslint/no-var-requires

chai.use(chaiAsPromised)

declare function expect(val: any, message?: string): any

/*  eslint-disable @typescript-eslint/no-unsafe-return, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call */
describe('ecies', () => {
  describe('kdf', () => {
    it('should find fragment for known secret keys', async () => {
      const secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex')
      const found = await ecies.kdf(secret, 32)
      const expected = Buffer.from('447b68d2586f66932558575fcf9eb0ea0c3f30fe6a6915d75756fee95826a6be', 'hex')

      return found.should.eqls(expected)
    })
    it('should round the ouput length to the next 32 mutiple', async () => {
      const secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex')
      const found1 = await ecies.kdf(secret, 35)
      const found2 = await ecies.kdf(secret, 64)

      return found1.should.eqls(found2)
    })
    it('should return an empty buffer for optoutLength = 0', async () => {
      const secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex')
      const found = await ecies.kdf(secret, 0)
      const expected = Buffer.from('')

      return found.should.eqls(expected)
    })
  })
  describe('getPublic', () => {
    it('should return a 65 bytes Buffer', async () => {
      const secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex')
      const found = await ecies.getPublic(secret)

      return found.should.have.lengthOf(65)
    })
    it('should accept a buffer of length 32 as parameter', () => {
      const secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex')
      const found = ecies.getPublic(secret)

      return expect(found)
    })
    it('should NOT accept a smaller buffer as parameter', () => {
      const smallerSecret = Buffer.from('b9fc3b425d6c1745b9c9631d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex')
      const found = ecies.getPublic(smallerSecret)

      return expect(found).to.be.rejectedWith('Private key should be 32 bytes long')
    })
    it('should NOT accept a larger buffer as parameter', () => {
      const largerSecret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a098779eecc', 'hex')
      const found = ecies.getPublic(largerSecret)

      return expect(found).to.be.rejectedWith('Private key should be 32 bytes long')
    })
    it('should be possible to derive a newly generated key', async () => {
      const secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex')
      const foundPublic = await ecies.getPublic(secret)
      const derived = ecies.derive(secret, foundPublic)

      return expect(derived).to.be.fulfilled
    })
  })
  describe('sign', () => {
    it('should accept a 32 bytes buffer as first parameter', () => {
      const secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex')
      const msg = Buffer.alloc(10)
      const found = ecies.sign(secret, msg)

      return expect(found).to.be.fulfilled
    })
    it('should NOT accept smaller buffer', () => {
      const smallerSecret = Buffer.from('b9fc3b425d6c1745b9c9631d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex')
      const msg = Buffer.alloc(10)
      const found = ecies.sign(smallerSecret, msg)

      return expect(found).to.be.rejectedWith('Private key should be 32 bytes long')
    })
    it('should NOT accept a larger buffer', () => {
      const largerSecret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a098779eecc', 'hex')
      const msg = Buffer.alloc(10)
      const found = ecies.sign(largerSecret, msg)

      return expect(found).to.be.rejectedWith('Private key should be 32 bytes long')
    })
    it('should NOT accept an empty message', () => {
      const secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex')
      const msg = Buffer.alloc(0)
      const found = ecies.sign(secret, msg)

      return expect(found).to.be.rejectedWith('Message should not be empty')
    })
    it('should NOT accept a message larger than 32 bytes', () => {
      const secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex')
      const msg = Buffer.alloc(33)
      const found = ecies.sign(secret, msg)

      return expect(found).to.be.rejectedWith('Message is too long (max 32 bytes)')
    })
    it('should accept a message between 1 and 32 bytes in length, included', () => {
      const secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex')
      const msg = Buffer.from('ROOOT')
      const found = ecies.sign(secret, msg)

      return expect(found).to.be.fulfilled
    })
  })
  describe('verify', () => {
    it('should accept a public key of 65 bytes', () => {
      const pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')
      const msg = Buffer.from('ROOOT')
      const sign = Buffer.from('30440220150285ea5a92decb327cba6d1065191ba7c28ed1430c0d75aec7cf37e9b2fd6a02200efdb6974ae5e728405f7893d5fc6ed5ce3823fb429119a66e2cdb438dd50233', 'hex')
      const found = ecies.verify(pub, msg, sign)

      return expect(found).to.be.fulfilled
    })
    it('should NOT accept a public key smaller than 65 bytes', () => {
      const smallerPub = Buffer.from('04e315a987bd79b9f49d3a1c8bdda81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')
      const msg = Buffer.from('ROOOT')
      const sign = Buffer.from('30440220150285ea5a92decb327cba6d1065191ba7c28ed1430c0d75aec7cf37e9b2fd6a02200efdb6974ae5e728405f7893d5fc6ed5ce3823fb429119a66e2cdb438dd50233', 'hex')
      const found = ecies.verify(smallerPub, msg, sign)

      return expect(found).to.be.rejectedWith('Public key should 65 bytes long')
    })
    it('should NOT accept a public key larger than 65 bytes', () => {
      const largerPub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a396842564', 'hex')
      const msg = Buffer.from('ROOOT')
      const sign = Buffer.from('30440220150285ea5a92decb327cba6d1065191ba7c28ed1430c0d75aec7cf37e9b2fd6a02200efdb6974ae5e728405f7893d5fc6ed5ce3823fb429119a66e2cdb438dd50233', 'hex')
      const found = ecies.verify(largerPub, msg, sign)

      return expect(found).to.be.rejectedWith('Public key should 65 bytes long')
    })
    it('should NOT accept an empty message', () => {
      const pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')
      const msg = Buffer.from('')
      const sign = Buffer.from('30440220150285ea5a92decb327cba6d1065191ba7c28ed1430c0d75aec7cf37e9b2fd6a02200efdb6974ae5e728405f7893d5fc6ed5ce3823fb429119a66e2cdb438dd50233', 'hex')
      const found = ecies.verify(pub, msg, sign)

      return expect(found).to.be.rejectedWith('Message should not be empty')
    })
    it('should NOT accept a message larger than 32 bytes', () => {
      const pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')
      const msg = pub //65 bytes
      const sign = Buffer.from('30440220150285ea5a92decb327cba6d1065191ba7c28ed1430c0d75aec7cf37e9b2fd6a02200efdb6974ae5e728405f7893d5fc6ed5ce3823fb429119a66e2cdb438dd50233', 'hex')
      const found = ecies.verify(pub, msg, sign)

      return expect(found).to.be.rejectedWith('Message is too long (max 32 bytes)')
    })
    it('should be in error in case of unmatching msg and sign', () => {
      const pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')
      const msg = Buffer.from('NOT ROOOT')
      const sign = Buffer.from('30440220150285ea5a92decb327cba6d1065191ba7c28ed1430c0d75aec7cf37e9b2fd6a02200efdb6974ae5e728405f7893d5fc6ed5ce3823fb429119a66e2cdb438dd50233', 'hex')
      const found = ecies.verify(pub, msg, sign)

      return expect(found).to.be.rejectedWith('Bad signature')
    })
    it('should be resolved with true in case of matching msg and sign', async () => {
      const pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')
      const msg = Buffer.from('ROOOT')
      const sign = Buffer.from('30440220150285ea5a92decb327cba6d1065191ba7c28ed1430c0d75aec7cf37e9b2fd6a02200efdb6974ae5e728405f7893d5fc6ed5ce3823fb429119a66e2cdb438dd50233', 'hex')
      const found = await ecies.verify(pub, msg, sign)

      return expect(found).to.be.true
    })
    it('should NOT accept any invalid signature', () => {
      const pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')
      const msg = Buffer.from('ROOOT')
      const sign = Buffer.from('this-is-not-a-signature')
      const found = ecies.verify(pub, msg, sign)

      return expect(found).to.be.rejectedWith('Invalid arguments')
    })
  })
  describe('derive', () => {
    it('should accept a private key 32 bytes long and a public key 65 bytes long', () => {
      const secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex')
      const pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')
      const found = ecies.derive(secret, pub)

      return expect(found).to.be.fulfilled
    })
    it('should NOT accept a secret key smaller than 32 bytes', () => {
      const smallerSecret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a37c0bf85dc1130b8a0', 'hex')
      const pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')
      const found = ecies.derive(smallerSecret, pub)

      return expect(found).to.be.rejectedWith(`Bad private key, it should be 32 bytes but it's actually ${smallerSecret.length} bytes long`)
    })
    it('should NOT accept a secret key larger than 32 bytes', () => {
      const largerSecret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a05773623846', 'hex')
      const pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')
      const found = ecies.derive(largerSecret, pub)

      return expect(found).to.be.rejectedWith(`Bad private key, it should be 32 bytes but it's actually ${largerSecret.length} bytes long`)
    })
    it('should NOT accept a public key larger than 65 bytes', () => {
      const secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex')
      const largerPub = Buffer.from('04e315a987bd79b9f49d6372748723a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')
      const found = ecies.derive(secret, largerPub)

      return expect(found).to.be.rejectedWith(`Bad public key, it should be 65 bytes but it's actually ${largerPub.length} bytes long`)
    })
    it('should NOT accept a public key smaller than 65 bytes', () => {
      const secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex')
      const smallerPub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a24222505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')
      const found = ecies.derive(secret, smallerPub)

      return expect(found).to.be.rejectedWith(`Bad public key, it should be 65 bytes but it's actually ${smallerPub.length} bytes long`)
    })
    it('should NOT accept a public key begginning with something else than 4', () => {
      const secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex')
      const smallerPub = Buffer.from('03e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')
      const found = ecies.derive(secret, smallerPub)

      return expect(found).to.be.rejectedWith('Bad public key, a valid public key would begin with 4')
    })
    it('should derive a new shared secret', async () => {
      const secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex')
      const pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')
      const found = await ecies.derive(secret, pub)
      const expected = Buffer.from('38b23cedbacdd74cc6faf140d4103daa57cf717703b043ad1b93da0c18d9f7ed', 'hex')

      return found.should.eqls(expected)
    })
  })
  describe('encrypt', () => {
    it('should accept public key 65 bytes long and a message between 1 and 32 bytes included', () => {
      const pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')
      const msg = Buffer.from('ROOOT')
      const found = ecies.encrypt(pub, msg)

      return expect(found).to.be.fulfilled
    })
    it('should NOT accept a public key larger than 65 bytes', () => {
      const largerPub = Buffer.from('04e315a987bd79b9f49d6372748723a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')
      const msg = Buffer.from('ROOOT')
      const found = ecies.encrypt(largerPub, msg)

      return expect(found).to.be.rejectedWith(`Bad public key, it should be 65 bytes but it's actually ${largerPub.length} bytes long`)
    })
    it('should NOT accept a public key smaller than 65 bytes', () => {
      const smallerPub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a24222505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')
      const msg = Buffer.from('ROOOT')
      const found = ecies.encrypt(smallerPub, msg)

      return expect(found).to.be.rejectedWith(`Bad public key, it should be 65 bytes but it's actually ${smallerPub.length} bytes long`)
    })
    it('should NOT accept a public key beginning with something else than 4', () => {
      const smallerPub = Buffer.from('03e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')
      const msg = Buffer.from('ROOOT')
      const found = ecies.encrypt(smallerPub, msg)

      return expect(found).to.be.rejectedWith('Bad public key, a valid public key would begin with 4')
    })
    it('should accept a opts.ephemPrivateKey of 32 bytes', () => {
      const secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex')
      const pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')
      const msg = Buffer.from('ROOOT')
      const found = ecies.encrypt(pub, msg, { ephemPrivateKey: secret })

      return expect(found).to.be.fulfilled
    })
    it('should NOT accept a opts.ephemPrivateKey smaller than 32 bytes', () => {
      const smallerSecret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a37c0bf85dc1130b8a0', 'hex')
      const pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')
      const msg = Buffer.from('ROOOT')
      const found = ecies.encrypt(pub, msg, { ephemPrivateKey: smallerSecret })

      return expect(found).to.be.rejectedWith(`Bad private key, it should be 32 bytes but it's actually ${smallerSecret.length} bytes long`)
    })
    it('should NOT accept a opts.ephemPrivateKey larger than 32 bytes', () => {
      const largerSecret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a05773623846', 'hex')
      const pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')
      const msg = Buffer.from('ROOOT')
      const found = ecies.encrypt(pub, msg, { ephemPrivateKey: largerSecret })

      return expect(found).to.be.rejectedWith(`Bad private key, it should be 32 bytes but it's actually ${largerSecret.length} bytes long`)
    })
    it('should NOT be deterministic', async () => {
      const pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')
      const msg = Buffer.from('ROOOT')
      const found1 = await ecies.encrypt(pub, msg)
      const found2 = await ecies.encrypt(pub, msg)

      return found1.should.not.eqls(found2)
    })
  })
  describe('decrypt', () => {
    const metaLength = 1 + 64 + 16 + 32
    it('should accept a 32 bytes private key with an encrypted message', () => {
      const secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex')
      const encrypted = Buffer.from('041891f11182f69dfd67dc190ccd649445182c6474f69c9f3885c99733b056fb53e1a30b90b6d2a2624449fda885adcba50334024b20081b07f95f3cc92a93dbedccf75890cd7ac088b0810058c272ef25a4028875342c5dfc36b54f156cd26b69109625e5374bc689c79196d98ccc9ad5b7099e6484', 'hex')
      const found = ecies.decrypt(secret, encrypted)

      return expect(found)
    })
    it('should NOT accept a secret key smaller than 32 bytes', () => {
      const smallerSecret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a37c0bf85dc1130b8a0', 'hex')
      const encrypted = Buffer.from('041891f11182f69dfd67dc190ccd649445182c6474f69c9f3885c99733b056fb53e1a30b90b6d2a2624449fda885adcba50334024b20081b07f95f3cc92a93dbedccf75890cd7ac088b0810058c272ef25a4028875342c5dfc36b54f156cd26b69109625e5374bc689c79196d98ccc9ad5b7099e6484', 'hex')
      const found = ecies.decrypt(smallerSecret, encrypted)

      return expect(found).to.be.rejectedWith(`Bad private key, it should be 32 bytes but it's actually ${smallerSecret.length} bytes long`)
    })
    it('should NOT accept a secret key larger than 32 bytes', () => {
      const largerSecret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a05773623846', 'hex')
      const encrypted = Buffer.from('041891f11182f69dfd67dc190ccd649445182c6474f69c9f3885c99733b056fb53e1a30b90b6d2a2624449fda885adcba50334024b20081b07f95f3cc92a93dbedccf75890cd7ac088b0810058c272ef25a4028875342c5dfc36b54f156cd26b69109625e5374bc689c79196d98ccc9ad5b7099e6484', 'hex')
      const found = ecies.decrypt(largerSecret, encrypted)

      return expect(found).to.be.rejectedWith(`Bad private key, it should be 32 bytes but it's actually ${largerSecret.length} bytes long`)
    })
    it('should NOT accept an encrypted msg beginning with a false public key', () => {
      const secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex')
      const encryptedWithFalsePublicKey = Buffer.from('031891f11182f69dfd67dc190ccd649445182c6474f69c9f3885c99733b056fb53e1a30b90b6d2a2624449fda885adcba50334024b20081b07f95f3cc92a93dbedccf75890cd7ac088b0810058c272ef25a4028875342c5dfc36b54f156cd26b69109625e5374bc689c79196d98ccc9ad5b7099e6484', 'hex')
      const found = ecies.decrypt(secret, encryptedWithFalsePublicKey)

      return expect(found).to.be.rejectedWith('Not a valid ciphertext. It should begin with 4 but actually begin with 3')
    })
    it(`should NOT accept an encrypted msg smaller than ${metaLength} bytes`, () => {
      const secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex')
      const smallerEncrypted = Buffer.from('041891f11182f69dfd67dc190c1a30b90b6d2a2624449fda885adcba50334024b20081b07f95f3cc92a93dbedccf75890cd7ac088b0810058c272ef25a4028875342c5dfc36b54f156cd26b69109625e5374bc689c79196d98ccc9ad5b7099e6484', 'hex')
      const found = ecies.decrypt(secret, smallerEncrypted)

      return expect(found).to.be.rejectedWith('Invalid Ciphertext. Data is too small. It should ba at least 113 bytes')
    })
  })
  describe('encrypt and decrypt', () => {
    it('should be invariant', async () => {
      const pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')
      const expected = 'ROOOT'
      const msg = Buffer.from(expected)
      const encrypted = await ecies.encrypt(pub, msg)
      const secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex')
      const decrypted = await ecies.decrypt(secret, encrypted)

      return decrypted.toString().should.eqls(expected)
    })
    it('should fail to decrypt if encrypted with another keypair', async () => {
      const msg = Buffer.from('Edgewhere')
      const owner1Pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')

      const encrypted = await ecies.encrypt(owner1Pub, msg)

      const owner2Secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c')
      const decrypted = ecies.decrypt(owner2Secret, encrypted)
      return expect(decrypted).to.be.rejectedWith('Incorrect MAC')
    })
  })
  describe('sign and verify', () => {
    it('shoud be invariant', async () => {
      const expected = 'ROOOT'
      const msg = Buffer.from(expected)
      const secret = Buffer.from('b9fc3b425d6c1745b9c963c97e6e1d4c1db7a093a36e0cf7c0bf85dc1130b8a0', 'hex')
      const signed = await ecies.sign(secret, msg)
      const pub = Buffer.from('04e315a987bd79b9f49d3a1c8bd1ef5a401a242820d52a3f22505da81dfcd992cc5c6e2ae9bc0754856ca68652516551d46121daa37afc609036ab5754fe7a82a3', 'hex')
      const found = await ecies.verify(pub, msg, signed)

      return expect(found).to.be.true
    })
  })
})
describe('KeyPath', () => {
  it('should reject wrong values at instantiation', () => {
    return expect(() => ecies.KeyPath('wrong-key-path')).to.throw(Error, 'invalid value for path')
  })
  it('should reject path exceeding limits', () => {
    return expect(() => ecies.KeyPath('m/0\'/0/2097152')).to.throw(Error, 'invalid path with value exceeding its limits')
  })
  describe('next', () => {
    it('should return the correct next path', () => {
      const expected = 'm/0\'/0/124'
      const found = ecies.KeyPath('m/0\'/0/123').next().value
      return found.should.equal(expected)
    })
  })
  describe('parse', () => {
    it('should return the right Path object', () => {
      const expected = ecies.Path('2\'', '0', '123')
      const found = ecies.KeyPath('m/2\'/0/123').parse()
      return found.should.eqls(expected)
    })
  })
  describe('valueOf', () => {
    it('should allow for appropriate comparison of paths', () => {
      const smaller = ecies.KeyPath('m/0\'/0/1234')
      const bigger = ecies.KeyPath('m/0\'/1/0')
      return expect(bigger.valueOf() > smaller.valueOf()).to.be.true
    })
    it('should give the actual value behind the path', () => {
      const expected = 2097152
      const found = ecies.KeyPath('m/0\'/1/0').valueOf()
      return found.should.equal(expected)
    })
  })
})
/*  eslint-enable @typescript-eslint/no-unsafe-call, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-return */
