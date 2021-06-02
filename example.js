const certnode = require('certnode')
const fs = require('fs')
const https = require('https')

const main = async () => {
  const client = new certnode.Client()

  // Generate fresh account keys for Let's Encrypt
  await client.generateAccountKeyPair()

  {
    // Generate privateKey and certificate for `domain` with `email` address.
    // Then, initialize HTTPS server with the credentials.
    const { certificate, privateKeyData } = await client.generateCertificate('<domain>', '<email>')
    const server = https.createServer({ cert: certificate, key: privateKeyData })

    /* register event listeners */

    server.listen(443, '0.0.0.0')

    // Export the account keys and write them to files in a directory.
    // Account private key is encrypted with passphrase, if provided.
    await client.exportAccountKeypair('<directory>', '[passphrase]')

    // Export private key and write it + certificate to filesystem.
    // Certificate private key is encrypted with passphrase, if provided.
    await Promise.all([
      fs.promises.writeFile('/path/to/certificate', certificate),
      certnode.writeKeyToFile('/path/to/privateKey', privateKeyData, '[passphrase]')
    ])
  }

  // Later: create another client for same account
  const anotherClient = new certnode.Client()

  // If you previously exported with passphrase, provide the same passphrase.
  await anotherClient.importAccountKeyPair('<directory>', '[passphrase]')

  /* generate certificate with `anotherClient` */

  // Later: import private key and certificate and initialize HTTPS server with them.
  const [certificate, privateKeyData] = await Promise.all([
    fs.promises.readFile('/path/to/certificate', 'utf8'),
    fs.promises.readFile('/path/to/privateKey', 'utf8')
  ])

  // If you previously exported with passphrase, provide the same passphrase.
  const server = https.createServer({
    cert: certificate,
    key: privateKeyData,
    passphrase: '[passphrase]'
  })

  /* register event listeners */

  server.listen(443, '0.0.0.0')
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})
