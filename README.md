# certnode

Generate [Let's Encrypt](https://letsencrypt.org/) certificates in Node!

## Why?

I wanted to see how difficult it is to generate Let's Encrypt certificates in Node without using an external package like [`greenlock`](https://www.npmjs.com/package/greenlock) or `exec`-ing [`certbot`](https://certbot.eff.org/) in child processes.

Essentially this boils down to creating keypairs, signing and sending HTTPS requests to Let's Encrypt's API endpoints. Not a huge lift; however, `certnode` is pretty limited right now. Extending functionality might be a larger effort.

This was primarily a learning exercise but also an effort to create a package that hopefully makes it easy for others to generate certificates for their domains :)

## Install

`npm i certnode`

## Usage

The following example code can be found [here](./example.js).

**Note:** you *must* control the domain + email address you pass to `client.generateCertificate()`. Also, be sure to allow inbound HTTP traffic (TCP, port 80) in your firewall rules.

### Generate account keys

```js
const certnode = require('certnode')
const fs = require('fs')
const https = require('https')

const client = new certnode.Client()

// Generate fresh account keys for Let's Encrypt
await client.generateAccountKeyPair()
```

### Generate certificate for HTTPS server

```js
const { certificate, privateKey } = await client.generateCertificate('<domain>', '<email>')
const server = https.createServer({ cert: certificate, key: privateKey })

/* register event listeners */

server.listen(443, '0.0.0.0')
```

### Export account keys to filesytem

```js
// Account private key is encrypted with passphrase, if provided.
await client.exportAccountKeypair('<directory>', '[passphrase]')
```

### Export certificate + private key to filesystem

```js
// Certificate private key is encrypted with passphrase, if provided.
const privateKeyData = certnode.exportPrivateKey('[passphrase]')

await Promise.all([
  fs.promises.writeFile('/path/to/certificate', certificate),
  fs.promises.writeFile('/path/to/privateKey', privateKeyData)
])
```

### Import account keys

```js
const anotherClient = new certnode.Client()

// If you previously exported with passphrase, provide the same passphrase.
await anotherClient.importAccountKeyPair('<directory>', '[passphrase]')

/* generate certificate with `anotherClient` */
```

### Import certificate + private key and initialize HTTPS server

```js
const [certificate, privateKeyData] = await Promise.all([
  fs.promises.readFile('/path/to/certificate', 'utf8'),
  fs.promises.readFile('/path/to/privateKey', 'utf8')
])

// If you previously exported with passphrase, provide the same passphrase.
const privateKey = certnode.importPrivateKey(privateKeyData, '[passphrase]')
const server = https.createServer({ cert: certificate, key: privateKey })

/* register event listeners */

server.listen(443, '0.0.0.0')
```

## Documentation

To generate the API docs:

`npm run docs`

Then open `./out/index.html` in your browser.

## Test

`sudo domain=<domain> npm test`

The test suite sends HTTPS requests to Let's Encrypt (staging environment) and generates certificates.

Therefore, tests *must* run from a `domain` you control, presumably on a VPS. Since `certnode` attains certificates through HTTP validation, it must run as root so it can listen on port 80. Make sure firewall rules allow this traffic.

**Note:** if you run tests several times in quick succession, you may be rate-limited by Let's Encrypt.

## Linting

`npm run lint`

## Resources

* [RFC 8555](https://datatracker.ietf.org/doc/rfc8555/)
