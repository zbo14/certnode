# certnode

Generate [Let's Encrypt](https://letsencrypt.org/) certificates in Node!

## Install

`npm i certnode`

## Usage

### Generate a TLS certificate

**Note:** you *must* control the domain you pass to `client.generateCertificate()` and allow inbound HTTP traffic (port 80) in your firewall rules.

```js
const { Client } = require('certnode')

const main = async () => {
  const client = new Client()

  await client.generateAccountKeyPair()

  const { certificate, privateKey } = await client.generateCertificate('<domain>', '<email>')

  // do something with certificate and privateKey
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})
```

TODO: more examples

## Resources

* [RFC 8555](https://datatracker.ietf.org/doc/rfc8555/)
