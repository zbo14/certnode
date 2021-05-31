'use strict'

const Client = require('../lib/client')

const { domain, email } = process.env

const main = async () => {
  const client = new Client()

  await client.generateAccountKeyPair()
  const result = await client.generateCertificate(domain, email)

  console.log(result)
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})
