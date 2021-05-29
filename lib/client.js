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
    this.directoryUrl = directoryUrl
    this.myAccountUrl = ''
    this.newAccountUrl = ''
    this.newNonceUrl = ''
    this.newOrderUrl = ''
    this.publicJwk = null
    this.privateJwk = null
    this.publicKey = null
    this.privateKey = null
    this.replayNonce = ''
    this.thumbprint = ''
  }

  async directory () {
    const res = await util.request(this.directoryUrl)

    if (res.statusCode !== 200) {
      throw new Error(`directory() Status Code: ${res.statusCode} Data: ${res.data}`)
    }

    const data = JSON.parse(res.data)
    this.newAccountUrl = data.newAccount
    this.newNonceUrl = data.newNonce
    this.newOrderUrl = data.newOrder
  }

  async importKeyPair (dirname, passphrase) {
    const [publicKeyData, privateKeyData] = await Promise.all([
      fs.promises.readFile(path.join(dirname, 'publicKey.pem'), 'utf8'),
      fs.promises.readFile(path.join(dirname, 'privateKey.pem'), 'utf8')
    ])

    try {
      this.publicKey = crypto.createPublicKey({
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
      this.privateKey = crypto.createPrivateKey(privateKeyOpts)
    } catch {
      throw new Error('Failed to load private key')
    }

    await this.initJwks()
  }

  exportPrivateKey (passphrase) {
    const privateKeyOpts = {
      type: 'pkcs1',
      format: 'pem'
    }

    if (passphrase) {
      privateKeyOpts.cipher = 'aes-256-cbc'
      privateKeyOpts.passphrase = passphrase
    }

    return this.privateKey.export(privateKeyOpts)
  }

  exportKeyPair (dirname, passphrase) {
    const publicKeyData = this.publicKey.export({
      type: 'pkcs1',
      format: 'pem'
    })

    const privateKeyData = this.exportPrivateKey(passphrase)

    return Promise.all([
      fs.promises.writeFile(path.join(dirname, 'publicKey.pem'), publicKeyData),
      fs.promises.writeFile(path.join(dirname, 'privateKey.pem'), privateKeyData)
    ])
  }

  async generateKeyPair () {
    const { publicKey, privateKey } = await generateKeyPair(JWS_ALGORITHM)

    this.publicKey = publicKey
    this.privateKey = privateKey

    await this.initJwks()
  }

  async initJwks () {
    const [publicJwk, privateJwk] = await Promise.all([
      fromKeyLike(this.publicKey),
      fromKeyLike(this.privateKey)
    ])

    this.publicJwk = publicJwk
    this.privateJwk = privateJwk
    this.thumbprint = await calculateThumbprint(publicJwk)
  }

  async sign (header, payload) {
    let data

    if (payload) {
      data = await new SignJWT(payload)
        .setProtectedHeader({ alg: JWS_ALGORITHM, ...header })
        .sign(this.privateKey)
    } else {
      // SignJWT constructor only accepts object, but RFC8555 requires empty payload
      // Workaround: we manually pass empty Uint8Array to CompactSign constructor
      const sig = new CompactSign(new Uint8Array())
      sig.setProtectedHeader({ alg: JWS_ALGORITHM, ...header })
      data = await sig.sign(this.privateKey)
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

  async newAccount (...emails) {
    const data = await this.sign(
      {
        jwk: this.publicJwk,
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

  async newNonce () {
    const res = await util.request(this.newNonceUrl, { method: 'HEAD' })

    if (res.statusCode !== 200) {
      throw new Error(`newNonce() Status Code: ${res.statusCode} Data: ${res.data}`)
    }

    this.setReplayNonce(res)
  }

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
    const { authorizations: authzUrls, finalize: finalizeUrl } = JSON.parse(res.data)

    return {
      authzUrls,
      domains,
      finalizeUrl,
      orderUrl
    }
  }

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

    console.log(res.data)

    this.setReplayNonce(res)

    if (res.statusCode !== 200) {
      throw new Error(`authz() Status Code: ${res.statusCode} Data: ${res.data}`)
    }

    const { challenges } = JSON.parse(res.data)
    const challenge = challenges.find(({ type }) => type === 'http-01')

    return challenge
  }

  async respondChallenge (challenge) {
    let data = await this.sign(
      {
        kid: this.myAccountUrl,
        nonce: this.replayNonce,
        url: challenge.url
      },
      {}
    )

    let res = await util.request(challenge.url, {
      method: 'POST',

      headers: {
        'content-type': 'application/jose+json'
      },

      data
    })

    this.setReplayNonce(res)

    if (res.statusCode !== 200) {
      throw new Error(`respondChallenge() Status Code: ${res.statusCode} Data: ${res.data}`)
    }

    const server = http.createServer()

    await new Promise((resolve, reject) => {
      server
        .once('error', reject)
        .on('request', (req, res) => {
          if (req.method !== 'GET') {
            res.writeHead(405)
            res.writeHead('Method Not Allowed')
            return
          }

          if (req.url !== '/.well-known/acme-challenge/' + challenge.token) {
            res.writeHead(404)
            res.end('Not Found')
            return
          }

          res.writeHead(200, {
            'content-type': 'application/octet-stream'
          })

          res.end(challenge.token + '.' + this.thumbprint)
          resolve()
        })

      server.listen(80, '0.0.0.0')
    })

    server.close()

    data = await this.sign(
      {
        kid: this.myAccountUrl,
        nonce: this.replayNonce,
        url: challenge.url
      },
      {}
    )

    res = await util.request(challenge.url, {
      method: 'POST',

      headers: {
        'content-type': 'application/jose+json'
      },

      data
    })

    this.setReplayNonce(res)

    if (res.statusCode !== 200) {
      throw new Error(`respondChallenge() Status Code: ${res.statusCode} Data: ${res.data}`)
    }
  }

  async finalizeOrder (finalizeUrl, { commonName, email, passphrase } = {}) {
    const csr = await createCsr({
      clientKey: this.exportPrivateKey(passphrase),
      commonName,
      email
    })

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

    this.setReplayNonce(res)

    if (res.statusCode !== 200) {
      throw new Error(`finalizeOrder() Status Code: ${res.statusCode} Data: ${res.data}`)
    }

    const { certificate: certificateUrl } = JSON.parse(res.data)

    return { certificateUrl }
  }
}

module.exports = Client
