const assert = require('assert')
const crypto = require('crypto')
const fs = require('fs')
const path = require('path')
const Client = require('../lib/client')

const fixturesDir = path.join(__dirname, 'fixtures')
const keysDir = path.join(fixturesDir, 'keys')
const publicKeyFile = path.join(keysDir, 'publicKey.pem')
const privateKeyFile = path.join(keysDir, 'privateKey.pem')

describe('lib/client', function () {
  this.timeout(5e3)

  before(async () => {
    await fs.promises.mkdir(keysDir)
  })

  beforeEach(() => {
    this.client = new Client()
  })

  after(async () => {
    await fs.promises.rmdir(keysDir, { recursive: true })
  })

  describe('#generateKeyPair()', () => {
    it('generates keypair', async () => {
      await this.client.generateKeyPair()

      assert(this.client.publicKey instanceof crypto.KeyObject)
      assert(this.client.privateKey instanceof crypto.KeyObject)

      assert.strictEqual(this.client.publicJwk.constructor.name, 'Object')
      assert.strictEqual(this.client.privateJwk.constructor.name, 'Object')
    })
  })

  describe('#exportKeyPair()', () => {
    beforeEach(async () => {
      await this.client.generateKeyPair()
    })

    afterEach(async () => {
      await Promise.all([
        fs.promises.unlink(publicKeyFile),
        fs.promises.unlink(privateKeyFile)
      ])
    })

    it('exports keypair to directory', async () => {
      await this.client.exportKeyPair(keysDir)

      await fs.promises.access(publicKeyFile, fs.constants.F_OK)
      await fs.promises.access(privateKeyFile, fs.constants.F_OK)
    })

    it('encrypts private key with passphrase', async () => {
      await this.client.exportKeyPair(keysDir, 'foobar')

      await fs.promises.access(publicKeyFile, fs.constants.F_OK)
      await fs.promises.access(privateKeyFile, fs.constants.F_OK)
    })
  })

  describe('#importKeyPair()', () => {
    beforeEach(async () => {
      await this.client.generateKeyPair()

      this.publicKey = this.client.publicKey
      this.privateKey = this.client.privateKey

      this.publicJwk = this.client.publicJwk
      this.privateJwk = this.client.privateJwk
    })

    afterEach(async () => {
      await Promise.all([
        fs.promises.unlink(publicKeyFile),
        fs.promises.unlink(privateKeyFile)
      ])
    })

    it('imports keypair from directory', async () => {
      await this.client.exportKeyPair(keysDir)
      await this.client.importKeyPair(keysDir)

      assert.deepStrictEqual(this.client.publicJwk, this.publicJwk)
      assert.deepStrictEqual(this.client.privateJwk, this.privateJwk)

      assert.deepStrictEqual(this.client.publicKey, this.publicKey)
      assert.deepStrictEqual(this.client.privateKey, this.privateKey)
    })

    it('decrypts private key with passphrase', async () => {
      await this.client.exportKeyPair(keysDir, 'foobar')
      await this.client.importKeyPair(keysDir, 'foobar')

      assert.deepStrictEqual(this.client.publicJwk, this.publicJwk)
      assert.deepStrictEqual(this.client.privateJwk, this.privateJwk)

      assert.deepStrictEqual(this.client.publicKey, this.publicKey)
      assert.deepStrictEqual(this.client.privateKey, this.privateKey)
    })

    it('errors if passphrase incorrect', async () => {
      await this.client.exportKeyPair(keysDir, 'foobar')

      try {
        await this.client.importKeyPair(keysDir, 'foobaz')
        assert.fail('Should reject')
      } catch ({ message }) {
        assert.strictEqual(message, 'Failed to load private key')
      }
    })
  })

  describe('#directory()', () => {
    it('fetches directory listing', async () => {
      await this.client.directory()

      assert.strictEqual(this.client.newAccountUrl, 'https://acme-staging-v02.api.letsencrypt.org/acme/new-acct')
      assert.strictEqual(this.client.newNonceUrl, 'https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce')
      assert.strictEqual(this.client.newOrderUrl, 'https://acme-staging-v02.api.letsencrypt.org/acme/new-order')
    })
  })

  describe('#newNonce()', () => {
    beforeEach(async () => {
      await this.client.directory()
    })

    it('receives replay nonce', async () => {
      await this.client.newNonce()

      assert(this.client.replayNonce)
      assert.strictEqual(typeof this.client.replayNonce, 'string')
    })
  })

  describe('#newAccount()', () => {
    beforeEach(async () => {
      await Promise.all([
        this.client.directory(),
        this.client.generateKeyPair()
      ])

      await this.client.newNonce()
    })

    it('creates a new account', async () => {
      const isNew = await this.client.newAccount('foo@bar.com')

      assert.strictEqual(isNew, true)
      assert(/^https:\/\/acme-staging-v02\.api\.letsencrypt\.org\/acme\/acct\/\d+$/.test(this.client.myAccountUrl))

      assert(this.client.replayNonce)
      assert.strictEqual(typeof this.client.replayNonce, 'string')
    })

    it('uses existing account if public key recognized', async () => {
      await this.client.newAccount('foo@baz.com')
      const isNew = await this.client.newAccount('foo@baz.com')

      assert.strictEqual(isNew, false)
      assert(/^https:\/\/acme-staging-v02\.api\.letsencrypt\.org\/acme\/acct\/\d+$/.test(this.client.myAccountUrl))

      assert(this.client.replayNonce)
      assert.strictEqual(typeof this.client.replayNonce, 'string')
    })
  })

  describe('#newOrder()', () => {
    beforeEach(async () => {
      await Promise.all([
        this.client.directory(),
        this.client.generateKeyPair()
      ])

      await this.client.newNonce()
      await this.client.newAccount('foo@bar.com')
    })

    it('creates a new order', async () => {
      const { authzUrls, domains, finalizeUrl, orderUrl } = await this.client.newOrder('bar.com')

      assert.deepStrictEqual(domains, ['bar.com'])

      assert(/^https:\/\/acme-staging-v02\.api\.letsencrypt\.org\/acme\/order\/\d+\/\d+$/.test(orderUrl))
      assert(/^https:\/\/acme-staging-v02\.api\.letsencrypt\.org\/acme\/finalize\/\d+\/\d+$/.test(finalizeUrl))

      authzUrls.forEach(authzUrl => {
        assert(/^https:\/\/acme-staging-v02\.api\.letsencrypt\.org\/acme\/authz-v3\/\d+$/.test(authzUrl))
      })
    })
  })

  describe('#authz()', () => {
    beforeEach(async () => {
      await Promise.all([
        this.client.directory(),
        this.client.generateKeyPair()
      ])

      await this.client.newNonce()
      await this.client.newAccount('foo@bar.com')
      const { authzUrls } = await this.client.newOrder('bar.com')
      this.authzUrls = authzUrls
    })

    it('completes an authorization', async () => {
      const challenge = await this.client.authz(this.authzUrls[0])

      assert.strictEqual(challenge.type, 'http-01')
      assert.strictEqual(challenge.status, 'pending')
      assert.strictEqual(typeof challenge.token, 'string')
      assert(challenge.url.startsWith('https://acme-staging-v02.api.letsencrypt.org/acme/chall-v3'))
    })
  })

  // describe.only('#respondChallenge()', () => {
  //   beforeEach(async () => {
  //     await Promise.all([
  //       this.client.directory(),
  //       this.client.generateKeyPair()
  //     ])

  //     await this.client.newNonce()
  //     await this.client.newAccount('foo@bar.com')
  //     const { authzUrls, domains, finalizeUrl, orderUrl } = await this.client.newOrder('bar.com')
  //     this.challenge = await this.client.authz(authzUrls[0])
  //   })

  //   it('completes an authorization', async () => {
  //     const challenge = await this.client.respondChallenge(this.challenge)

  //     assert.strictEqual(challenge.type, 'http-01')
  //     assert.strictEqual(challenge.status, 'pending')
  //     assert.strictEqual(typeof challenge.token, 'string')
  //     assert(challenge.url.startsWith('https://acme-staging-v02.api.letsencrypt.org/acme/chall-v3'))
  //   })
  // })

  // describe('#finalizeOrder()', () => {
  //   beforeEach(async () => {
  //     await Promise.all([
  //       this.client.directory(),
  //       this.client.generateKeyPair()
  //     ])

  //     await this.client.newNonce()
  //     await this.client.newAccount('foo@bar.com')
  //     const { finalizeUrl, orderUrl } = await this.client.newOrder('bar.com')
  //     this.finalizeUrl = finalizeUrl
  //   })

  //   it('finalizes order', async () => {
  //     const { certifcateUrl } = await this.client.finalizeOrder(this.finalizeUrl, 'bar.com', 'foo@bar.com')

  //     assert(/^https:\/\/acme-staging-v02\.api\.letsencrypt\.org\/acme\/certificate\/\d+\/\d+$/.test(certificateUrl))
  //   })
  // })
})
