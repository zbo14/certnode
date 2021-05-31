const crypto = require('crypto')
const fs = require('fs')
const http = require('http')
const path = require('path')
const { promisify } = require('util')
const { fromKeyLike } = require('jose-node-cjs-runtime/jwk/from_key_like')
const { generateKeyPair } = require('jose-node-cjs-runtime/util/generate_key_pair')
const { calculateThumbprint } = require('jose-node-cjs-runtime/jwk/thumbprint')
const { SignJWT } = require('jose-node-cjs-runtime/jwt/sign')
const { CompactSign } = require('jose-node-cjs-runtime/jws/compact/sign')
const pem = require('pem')
const util = require('./util')

const createCsr = promisify(pem.createCSR)

const DIRECTORY_URL = 'https://acme-staging-v02.api.letsencrypt.org/directory'
const JWS_ALGORITHM = 'RS256'

class Client {
  constructor (directoryUrl = DIRECTORY_URL) {
    this.accountPublicJwk = null
    this.accountPrivateJwk = null
    this.accountPublicKey = null
    this.accountPrivateKey = null
    this.directoryUrl = directoryUrl
    this.myAccountUrl = ''
    this.newAccountUrl = ''
    this.newNonceUrl = ''
    this.newOrderUrl = ''
    this.replayNonce = ''
    this.server = null
    this.thumbprint = ''
  }

  /**
   * @param  {String} domain
   * @param  {String} email
   * @param  {Object} [keypair]
   * @param  {String} keypair.dirname
   * @param  {String} [keypair.passphrase]
   *
   * @return {Promise}
   */
  async generateCertificate (domain, email, keypair) {
    const promise1 = this.directory()

    const promise2 = keypair
      ? this.importAccountKeyPair(keypair.dirname, keypair.passphrase)
      : this.generateAccountKeyPair()

    await Promise.all([promise1, promise2])

    await this.newNonce()
    await this.newAccount(email)
    const { authzUrls, finalizeUrl } = await this.newOrder(domain)
    const { challenge } = await this.authz(authzUrls[0])

    await this.completeChallenge(challenge)
    await this.pollAuthz(authzUrls[0])
    await this.finalizeOrder(finalizeUrl, domain, email, keypair?.passphrase)
  }

  async pollAuthz (authzUrl) {
    for (let i = 0; i < 10; i++) {
      const result = await this.authz(authzUrl)

      if (result.status === 'pending') {
        await new Promise(resolve => setTimeout(resolve, 1e3))
        continue
      }

      if (result.status === 'invalid') {
        throw new Error('pollAuthz() authorization is invalid')
      }

      return result
    }

    throw new Error('pollAuthz() timed out')
  }

  /**
   * @return {Promise}
   */
  async directory () {
    const res = await util.request(this.directoryUrl)

    if (res.statusCode !== 200) {
      throw new Error(`directory() Status Code: ${res.statusCode} Data: ${res.data}`)
    }

    this.newAccountUrl = res.data.newAccount
    this.newNonceUrl = res.data.newNonce
    this.newOrderUrl = res.data.newOrder
  }

  /**
   * @param  {String} dirname
   * @param  {String} [passphrase]
   *
   * @return {Promise}
   */
  async importAccountKeyPair (dirname, passphrase) {
    const [publicKeyData, privateKeyData] = await Promise.all([
      fs.promises.readFile(path.join(dirname, 'publicKey.pem'), 'utf8'),
      fs.promises.readFile(path.join(dirname, 'privateKey.pem'), 'utf8')
    ])

    try {
      this.accountPublicKey = crypto.createPublicKey({
        key: publicKeyData,
        format: 'pem',
        type: 'pkcs1'
      })
    } catch {
      throw new Error('Failed to load public key')
    }

    const privateKeyOpts = {
      key: privateKeyData,
      format: 'pem',
      type: 'pkcs1'
    }

    if (passphrase) {
      privateKeyOpts.passphrase = passphrase
    }

    try {
      this.accountPrivateKey = crypto.createPrivateKey(privateKeyOpts)
    } catch {
      throw new Error('Failed to load private key')
    }

    await this.initAccountJwks()
  }

  exportAccountPrivateKey (passphrase) {
    return Client.exportPrivateKey(this.accountPrivateKey)
  }

  static exportPrivateKey (privateKey, passphrase) {
    const privateKeyOpts = {
      type: 'pkcs1',
      format: 'pem'
    }

    if (passphrase) {
      privateKeyOpts.cipher = 'aes-256-cbc'
      privateKeyOpts.passphrase = passphrase
    }

    return privateKey.export(privateKeyOpts)
  }

  exportAccountKeyPair (dirname, passphrase) {
    const publicKeyData = this.accountPublicKey.export({
      type: 'pkcs1',
      format: 'pem'
    })

    const privateKeyData = this.exportAccountPrivateKey(passphrase)

    return Promise.all([
      fs.promises.writeFile(path.join(dirname, 'publicKey.pem'), publicKeyData),
      fs.promises.writeFile(path.join(dirname, 'privateKey.pem'), privateKeyData)
    ])
  }

  /**
   * @return {Promise}
   */
  async generateAccountKeyPair () {
    const { publicKey, privateKey } = await generateKeyPair(JWS_ALGORITHM)

    this.accountPublicKey = publicKey
    this.accountPrivateKey = privateKey

    await this.initAccountJwks()
  }

  async initAccountJwks () {
    const [publicJwk, accountPrivateJwk] = await Promise.all([
      fromKeyLike(this.accountPublicKey),
      fromKeyLike(this.accountPrivateKey)
    ])

    this.accountPublicJwk = publicJwk
    this.accountPrivateJwk = accountPrivateJwk
    this.thumbprint = await calculateThumbprint(publicJwk)
  }

  async sign (header, payload) {
    let data

    if (payload) {
      data = await new SignJWT(payload)
        .setProtectedHeader({ alg: JWS_ALGORITHM, ...header })
        .sign(this.accountPrivateKey)
    } else {
      // SignJWT constructor only accepts object but RFC8555 requires empty payload
      // Workaround: we manually pass empty Uint8Array to CompactSign constructor
      const sig = new CompactSign(new Uint8Array())
      sig.setProtectedHeader({ alg: JWS_ALGORITHM, ...header })
      data = await sig.sign(this.accountPrivateKey)
    }

    const [b64Header, b64Payload, b64Signature] = data.split('.')

    return JSON.stringify({
      protected: b64Header,
      payload: b64Payload,
      signature: b64Signature
    })
  }

  setReplayNonce (res) {
    const replayNonce = (res.headers['replay-nonce'] || '').trim()

    if (!replayNonce) {
      throw new Error('No Replay-Nonce header in response')
    }

    this.replayNonce = replayNonce
  }

  /**
   * @param  {...String} emails
   *
   * @return {Promise}
   */
  async newAccount (...emails) {
    const data = await this.sign(
      {
        jwk: this.accountPublicJwk,
        nonce: this.replayNonce,
        url: this.newAccountUrl
      },
      {
        contact: emails.map(email => 'mailto:' + email),
        termsOfServiceAgreed: true
      }
    )

    const res = await util.request(this.newAccountUrl, {
      method: 'POST',

      headers: {
        'content-type': 'application/jose+json'
      },

      data
    })

    this.setReplayNonce(res)

    if (![200, 201].includes(res.statusCode)) {
      throw new Error(`newAccount() Status Code: ${res.statusCode} Data: ${res.data}`)
    }

    this.myAccountUrl = res.headers.location

    return res.statusCode === 201
  }

  /**
   * @return {Promise}
   */
  async newNonce () {
    const res = await util.request(this.newNonceUrl, { method: 'HEAD' })

    if (res.statusCode !== 200) {
      throw new Error(`newNonce() Status Code: ${res.statusCode} Data: ${res.data}`)
    }

    this.setReplayNonce(res)
  }

  /**
   * @param  {...String} domains
   *
   * @return {Promise}
   */
  async newOrder (...domains) {
    const identifiers = domains.map(domain => ({ type: 'dns', value: domain }))

    const data = await this.sign(
      {
        kid: this.myAccountUrl,
        nonce: this.replayNonce,
        url: this.newOrderUrl
      },
      {
        identifiers
      }
    )

    const res = await util.request(this.newOrderUrl, {
      method: 'POST',

      headers: {
        'content-type': 'application/jose+json'
      },

      data
    })

    this.setReplayNonce(res)

    if (res.statusCode !== 201) {
      throw new Error(`newOrder() Status Code: ${res.statusCode} Data: ${res.data}`)
    }

    const orderUrl = res.headers.location
    const { authorizations: authzUrls, finalize: finalizeUrl } = res.data

    return {
      authzUrls,
      domains,
      finalizeUrl,
      orderUrl
    }
  }

  /**
   * @param  {String} authzUrl
   *
   * @return {Promise}
   */
  async authz (authzUrl) {
    const data = await this.sign(
      {
        kid: this.myAccountUrl,
        nonce: this.replayNonce,
        url: authzUrl
      }
    )

    const res = await util.request(authzUrl, {
      method: 'POST',

      headers: {
        'content-type': 'application/jose+json'
      },

      data
    })

    this.setReplayNonce(res)

    if (res.statusCode !== 200) {
      throw new Error(`authz() Status Code: ${res.statusCode} Data: ${res.data}`)
    }

    const { challenges, identifier, ...rest } = res.data
    const challenge = challenges.find(({ type }) => type === 'http-01')

    return {
      challenge,
      domain: identifier.value,
      ...rest
    }
  }

  receiveServerRequest (challenge) {
    this.server?.close()
    this.server = http.createServer()

    return new Promise((resolve, reject) => {
      this.server
        .once('error', reject)
        .on('request', (req, res) => {
          if (req.method !== 'GET') {
            res.writeHead(405)
            res.writeHead(http.STATUS_CODES[405])
            return
          }

          if (req.url !== '/.well-known/acme-challenge/' + challenge.token) {
            res.writeHead(404)
            res.end(http.STATUS_CODES[404])
            return
          }

          res.writeHead(200, {
            'content-type': 'application/octet-stream'
          })

          res.end(challenge.token + '.' + this.thumbprint)
          resolve()
        })

      this.server.listen(80, '0.0.0.0')
    })
  }

  async readyChallenge (challenge) {
    const data = await this.sign(
      {
        kid: this.myAccountUrl,
        nonce: this.replayNonce,
        url: challenge.url
      },
      {}
    )

    const res = await util.request(challenge.url, {
      method: 'POST',

      headers: {
        'content-type': 'application/jose+json'
      },

      data
    })

    this.setReplayNonce(res)

    if (res.statusCode !== 200) {
      throw new Error(`completeChallenge() Status Code: ${res.statusCode} Data: ${res.data}`)
    }
  }

  /**
   * @param  {Object} challenge
   * @param  {String} challenge.token
   * @param  {String} challenge.url
   *
   * @return {Promise}
   */
  async completeChallenge (challenge) {
    await this.readyChallenge(challenge)
    await this.receiveServerRequest(challenge)
  }

  /**
   * @param  {String} finalizeUrl
   * @param  {String} domain
   * @param  {String} email
   * @param  {String} [passphrase]
   *
   * @return {Promise}
   */
  async finalizeOrder (finalizeUrl, domain, email, passphrase) {
    const { privateKey } = await generateKeyPair(JWS_ALGORITHM)
    const clientKey = Client.exportPrivateKey(privateKey)
    let { csr } = await createCsr({ clientKey, commonName: domain, email })

    // "The CSR is sent in the base64url-encoded version of the DER format.
    // (Note: Because this field uses base64url, and does not include headers,
    // it is different from PEM.)"
    csr = csr
      .split('\n')
      .filter(Boolean)
      .slice(1, -1)
      .join('')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '')

    const data = await this.sign(
      {
        kid: this.myAccountUrl,
        nonce: this.replayNonce,
        url: finalizeUrl
      },
      {
        csr
      }
    )

    const res = await util.request(finalizeUrl, {
      method: 'POST',

      headers: {
        'content-type': 'application/jose+json'
      },

      data
    })

    console.log(res)

    this.setReplayNonce(res)

    if (res.statusCode !== 200) {
      throw new Error(`finalizeOrder() Status Code: ${res.statusCode} Data: ${res.data}`)
    }

    return {
      certificateUrl: res.data.certificate,
      clientKey
    }
  }
}

module.exports = Client
