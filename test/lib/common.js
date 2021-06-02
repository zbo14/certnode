const assert = require('assert')
const fs = require('fs')
const path = require('path')
const { generateKeyPair } = require('jose-node-cjs-runtime/util/generate_key_pair')
const common = require('../../lib/common')

const fixturesDir = path.resolve(__dirname, '..', 'fixtures')
const keysDir = path.join(fixturesDir, 'keys')

describe('lib/common', () => {
  describe('#exportPrivateKey()', () => {
    beforeEach(async () => {
      this.keyPair = await generateKeyPair(common.CERTIFICATE_KEY_ALGORITHM)
    })

    it('exports private key for certificate', async () => {
      const privateKeyData = common.exportPrivateKey(this.keyPair.privateKey)

      assert.strictEqual(typeof privateKeyData, 'string')
      assert(privateKeyData.startsWith('-----BEGIN PRIVATE KEY-----\n'))
      assert(privateKeyData.endsWith('-----END PRIVATE KEY-----\n'))
    })
  })

  describe('#writeKeyToFile()', () => {
    before(async () => {
      await fs.promises.mkdir(keysDir)
    })

    after(async () => {
      await fs.promises.rmdir(keysDir, { recursive: true })
    })

    beforeEach(async () => {
      this.keyPair = await generateKeyPair(common.CERTIFICATE_KEY_ALGORITHM)
    })

    it('writes privateKey and privateKeyData to filesystem', async () => {
      const privateKey = this.keyPair.privateKey
      const privateKeyData = common.exportPrivateKey(privateKey)

      await common.writeKeyToFile(keysDir, privateKeyData)
      const privateKeyData1 = await fs.promises.readFile(path.join(keysDir, 'privateKey.pem'), 'utf8')
      const privateKey1 = common.importPrivateKey(privateKeyData1)

      await common.writeKeyToFile(keysDir, privateKey, 'foobar')
      const privateKeyData2 = await fs.promises.readFile(path.join(keysDir, 'privateKey.pem'), 'utf8')
      const privateKey2 = common.importPrivateKey(privateKeyData2, 'foobar')

      assert.deepStrictEqual(privateKey1, privateKey2)
    })
  })
})
