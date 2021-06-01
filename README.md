# certnode

Generate [Let's Encrypt](https://letsencrypt.org/) certificates in Node!

## Install

`npm i certnode`

## Usage

### Generate a TLS certificate

```js
const { Client } = require('certnode')

const main = async () => {
  const client = new Client()

  await client.generateAccountKeyPair()

  const { certificate, privateKey } = await client.generateCertificate(
    '<domain>',
    '<email>',
    '[passphrase]'
  )

  // do something with certificate and privateKey
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})
```

## Resources

* [RFC 8555](https://datatracker.ietf.org/doc/rfc8555/)
