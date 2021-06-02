const certnode = require('./lib')
const fs = require('fs')
const https = require('https')
const path = require('path')

const {
  dirname = path.join(__dirname, 'private'),
  domain,
  email,
  passphrase = ''
} = process.env

if (!domain) {
  console.error('Must specify "domain"')
  process.exit(1)
}

if (!email) {
  console.error('Must specify "email"')
  process.exit(1)
}

const accountDir = path.join(dirname, 'account')
const domainDir = path.join(dirname, domain)

const certificateFile = path.join(domainDir, 'certificate.pem')
const privateKeyFile = path.join(domainDir, 'privateKey.pem')

const main = async () => {
  await Promise.all([
    fs.promises.mkdir(accountDir, { recursive: true }).catch(() => {}),
    fs.promises.mkdir(domainDir, { recursive: true }).catch(() => {})
  ])

  const client = new certnode.Client()

  // Generate fresh account keys for Let's Encrypt
  await client.generateAccountKeyPair()
  console.log('Generated account keys')

  {
    // Generate privateKey and certificate for `domain` with `email` address.
    // Then, initialize HTTPS server with the credentials.
    const { certificate, privateKeyData } = await client.generateCertificate(domain, email)
    console.log('Generated certificate and private key')

    const server = https.createServer({ cert: certificate, key: privateKeyData })

    /* register event listeners */

    server.listen(443, '0.0.0.0', () => {
      console.log('Started server with credentials')
      server.close()
    })

    // Export the account keys and write them to files in a directory.
    // Account private key is encrypted with passphrase, if provided.
    await client.exportAccountKeyPair(accountDir, passphrase)
    console.log('Exported account keys')

    // Export private key and write it + certificate to filesystem.
    // Certificate private key is encrypted with passphrase, if provided.
    await Promise.all([
      fs.promises.writeFile(certificateFile, certificate),
      certnode.writeKeyToFile(privateKeyFile, privateKeyData, passphrase)
    ])

    console.log('Exported certificate and private key')
  }

  // Later: create another client for same account
  const anotherClient = new certnode.Client()

  // If you previously exported with passphrase, provide the same passphrase.
  await anotherClient.importAccountKeyPair(dirname, passphrase)
  console.log('Imported account keys')

  /* generate certificate with `anotherClient` */

  // Later: import private key and certificate and initialize HTTPS server with them.
  const [certificate, privateKeyData] = await Promise.all([
    fs.promises.readFile(certificateFile, 'utf8'),
    fs.promises.readFile(privateKeyFile, 'utf8')
  ])

  console.log('Exported certificate and private key')

  // If you previously exported with passphrase, provide the same passphrase.
  const server = https.createServer({
    cert: certificate,
    key: privateKeyData,
    passphrase
  })

  /* register event listeners */

  server.listen(443, '0.0.0.0', () => {
    console.log('Started server with credentials')
    server.close()
  })
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})
