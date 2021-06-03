const assert = require('assert')
const crypto = require('crypto')
const fs = require('fs')
const path = require('path')
const fakeTimers = require('@sinonjs/fake-timers')
const Client = require('../../lib/client')
const common = require('../../lib/common')

const fixturesDir = path.resolve(__dirname, '..', 'fixtures')
const keysDir = path.join(fixturesDir, 'keys')
const privateKeyFile = path.join(keysDir, 'privateKey.pem')
const publicKeyFile = path.join(keysDir, 'publicKey.pem')

describe('lib/client', function () {
  this.timeout(10e3)

  before(async () => {
    await fs.promises.mkdir(keysDir)
  })

  beforeEach(() => {
    this.client = new Client()
    this.clock = fakeTimers.install()
  })

  after(async () => {
    await fs.promises.rmdir(keysDir, { recursive: true })
  })

  afterEach(() => {
    this.clock.uninstall()
  })

  describe('#exportAccountKeyPair()', () => {
    beforeEach(async () => {
      await this.client.generateAccountKeyPair()
    })

    afterEach(async () => {
      await Promise.all([
        fs.promises.unlink(publicKeyFile),
        fs.promises.unlink(privateKeyFile)
      ])
    })

    it('exports keypair to directory', async () => {
      await this.client.exportAccountKeyPair(keysDir)

      await fs.promises.access(privateKeyFile)
      await fs.promises.access(publicKeyFile)
    })

    it('encrypts private key with passphrase', async () => {
      await this.client.exportAccountKeyPair(keysDir, 'foobar')

      await fs.promises.access(privateKeyFile)
      await fs.promises.access(publicKeyFile)
    })
  })

  describe('#importAccountKeyPair()', () => {
    beforeEach(async () => {
      await this.client.generateAccountKeyPair()

      this.accountPublicKey = this.client.accountPublicKey
      this.accountPrivateKey = this.client.accountPrivateKey

      this.accountPublicJwk = this.client.accountPublicJwk
      this.accountPrivateJwk = this.client.accountPrivateJwk
    })

    afterEach(async () => {
      await Promise.all([
        fs.promises.unlink(publicKeyFile),
        fs.promises.unlink(privateKeyFile)
      ])
    })

    it('imports keypair from directory', async () => {
      await this.client.exportAccountKeyPair(keysDir)
      await this.client.importAccountKeyPair(keysDir)

      assert.deepStrictEqual(this.client.accountPublicJwk, this.accountPublicJwk)
      assert.deepStrictEqual(this.client.accountPrivateJwk, this.accountPrivateJwk)

      assert.deepStrictEqual(this.client.accountPublicKey, this.accountPublicKey)
      assert.deepStrictEqual(this.client.accountPrivateKey, this.accountPrivateKey)
    })

    it('decrypts private key with passphrase', async () => {
      await this.client.exportAccountKeyPair(keysDir, 'foobar')
      await this.client.importAccountKeyPair(keysDir, 'foobar')

      assert.deepStrictEqual(this.client.accountPublicJwk, this.accountPublicJwk)
      assert.deepStrictEqual(this.client.accountPrivateJwk, this.accountPrivateJwk)

      assert.deepStrictEqual(this.client.accountPublicKey, this.accountPublicKey)
      assert.deepStrictEqual(this.client.accountPrivateKey, this.accountPrivateKey)
    })

    it('errors if passphrase incorrect', async () => {
      await this.client.exportAccountKeyPair(keysDir, 'foobar')

      try {
        await this.client.importAccountKeyPair(keysDir, 'foobaz')
        assert.fail('Should reject')
      } catch ({ message }) {
        assert.strictEqual(message, 'Failed to import private key')
      }
    })
  })

  describe('#directory()', () => {
    it('fetches fresh directory listing', async () => {
      const result = await this.client.directory()

      assert.strictEqual(result, true)
      assert.strictEqual(this.client.newAccountUrl, 'https://acme-staging-v02.api.letsencrypt.org/acme/new-acct')
      assert.strictEqual(this.client.newNonceUrl, 'https://acme-staging-v02.api.letsencrypt.org/acme/new-nonce')
      assert.strictEqual(this.client.newOrderUrl, 'https://acme-staging-v02.api.letsencrypt.org/acme/new-order')
    })

    it('doesn\'t fetch multiple times', async () => {
      await this.client.directory()
      const result = await this.client.directory()

      assert.strictEqual(result, false)
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
      const result = await this.client.newNonce()

      assert.strictEqual(result, true)
      assert(this.client.replayNonce)
      assert.strictEqual(typeof this.client.replayNonce, 'string')
    })

    it('doesn\'t receive nonce multiple times', async () => {
      await this.client.newNonce()
      const result = await this.client.newNonce()

      assert.strictEqual(result, false)
      assert(this.client.replayNonce)
      assert.strictEqual(typeof this.client.replayNonce, 'string')
    })
  })

  describe('#newAccount()', () => {
    beforeEach(async () => {
      await Promise.all([
        this.client.directory(),
        this.client.generateAccountKeyPair()
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
        this.client.generateAccountKeyPair()
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
        this.client.generateAccountKeyPair()
      ])

      await this.client.newNonce()
      await this.client.newAccount('foo@bar.com')
      const { authzUrls } = await this.client.newOrder('bar.com')
      this.authzUrls = authzUrls
    })

    it('completes an authorization', async () => {
      const result = await this.client.authz(this.authzUrls[0])

      assert.strictEqual(result.challenge.type, 'http-01')
      assert.strictEqual(result.challenge.status, 'pending')
      assert.strictEqual(typeof result.challenge.token, 'string')
      assert(result.challenge.url.startsWith('https://acme-staging-v02.api.letsencrypt.org/acme/chall-v3'))
      assert.strictEqual(result.domain, 'bar.com')
      assert.strictEqual(result.status, 'pending')
    })
  })

  describe('#completeChallenge()', () => {
    beforeEach(async () => {
      await Promise.all([
        this.client.directory(),
        this.client.generateAccountKeyPair()
      ])

      await this.client.newNonce()
      await this.client.newAccount('foo@bar.com')

      const { authzUrls } = await this.client.newOrder(process.env.domain)
      const { challenge } = await this.client.authz(authzUrls[0])

      this.authzUrl = authzUrls[0]
      this.challenge = challenge
    })

    afterEach(() => {
      this.client.server?.close()
    })

    it('completes a challenge', async () => {
      await this.client.completeChallenge(this.challenge)
      const result = await this.client.pollAuthz(this.authzUrl)

      assert.strictEqual(result.challenge.type, 'http-01')
      assert.strictEqual(result.challenge.status, 'valid')
      assert.strictEqual(result.challenge.token, this.challenge.token)
      assert.strictEqual(result.challenge.url, this.challenge.url)
      assert.strictEqual(typeof result.challenge.validated, 'string')
      assert.strictEqual(result.domain, process.env.domain)
      assert.strictEqual(result.status, 'valid')
    })

    it('completes a challenge', async () => {
      const { authzUrls } = await this.client.newOrder('potato.com')
      const { challenge } = await this.client.authz(authzUrls[0])
      await this.client.completeChallenge(challenge)
      const promise = this.client.pollAuthz(authzUrls[0])

      this.clock.tick(10e3)

      try {
        await promise
        assert.fail('Should reject')
      } catch ({ message }) {
        assert.strictEqual(message, 'Timed out waiting for server request')
      }
    })
  })

  describe('#finalizeOrder()', () => {
    beforeEach(async () => {
      await Promise.all([
        this.client.directory(),
        this.client.generateAccountKeyPair()
      ])

      await this.client.newNonce()
      await this.client.newAccount('foo@bar.com')

      const { authzUrls, finalizeUrl } = await this.client.newOrder(process.env.domain)
      this.authzUrl = authzUrls[0]
      this.finalizeUrl = finalizeUrl

      const { challenge } = await this.client.authz(this.authzUrl)
      this.challenge = challenge

      await this.client.completeChallenge(this.challenge)
      await this.client.pollAuthz(this.authzUrl)
    })

    afterEach(() => {
      this.client.server?.close()
    })

    it('finalizes the order and fetches certificate', async () => {
      const result = await this.client.finalizeOrder(
        this.finalizeUrl,
        process.env.domain,
        'foo@bar.com'
      )

      const privateKey = common.importPrivateKey(result.privateKeyData)

      assert.strictEqual(typeof result.certificate, 'string')
      assert(result.certificate.startsWith('-----BEGIN CERTIFICATE-----\n'))
      assert(result.certificate.endsWith('-----END CERTIFICATE-----\n'))
      assert.strictEqual(typeof result.privateKeyData, 'string')
      assert(privateKey instanceof crypto.KeyObject)
      assert.strictEqual(privateKey.type, 'private')
    })
  })

  describe('#generateCertificate()', () => {
    beforeEach(async () => {
      await this.client.generateAccountKeyPair()
    })

    it('generates certificate given domain and email address', async () => {
      const result = await this.client.generateCertificate(process.env.domain, 'foo@bar.com')
      const privateKey = common.importPrivateKey(result.privateKeyData)

      assert.strictEqual(typeof result.certificate, 'string')
      assert(result.certificate.startsWith('-----BEGIN CERTIFICATE-----\n'))
      assert(result.certificate.endsWith('-----END CERTIFICATE-----\n'))
      assert.strictEqual(typeof result.privateKeyData, 'string')
      assert(privateKey instanceof crypto.KeyObject)
      assert.strictEqual(privateKey.type, 'private')
    })
  })
})
