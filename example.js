const certnode = require('./lib')
const fs = require('fs')
const https = require('https')

const main = async () => {
  const client = new certnode.Client()

  // Generate fresh account keys for Let's Encrypt
  await client.generateAccountKeyPair()

  {
    // Generate privateKey and certificate for `domain` with `email` address.
    // Then, initialize HTTPS server with the credentials.
    const { certificate, privateKey } = await client.generateCertificate('<domain>', '<email>')
    const server = https.createServer({ cert: certificate, key: privateKey })

    /* register event listeners */

    server.listen(443, '0.0.0.0')

    // Export the account keys and write them to files in a directory.
    // Account private key is encrypted with passphrase, if provided.
    await client.exportAccountKeypair('<directory>', '[passphrase]')

    // Export private key and write it + certificate to filesystem.
    // Certificate private key is encrypted with passphrase, if provided.
    const privateKeyData = certnode.exportPrivateKey('[passphrase]')

    await Promise.all([
      fs.promises.writeFile('/path/to/certificate', certificate),
      fs.promises.writeFile('/path/to/privateKey', privateKeyData)
    ])
  }

  // Later: create another client for same account
  const anotherClient = new certnode.Client()
  await anotherClient.importAccountKeyPair('<directory>', '[passphrase]')

  /* generate certificate with `anotherClient` */

  // Later: import private key and certificate and initialize HTTPS server with them.
  const [certificate, privateKeyData] = await Promise.all([
    fs.promises.writeFile('/path/to/certificate'),
    fs.promises.writeFile('/path/to/privateKey')
  ])

  // If you previously exported with passphrase, provide the same passprhase.
  const privateKey = certnode.importPrivateKey(privateKeyData, '[passphrase]')
  const server = https.createServer({ cert: certificate, key: privateKey })

  /* register event listeners */

  server.listen(443, '0.0.0.0')
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})
