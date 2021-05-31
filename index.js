const Client = require('./lib/client')

const main = async function () {
  const { domain, email } = process.env
  const client = new Client()
  await client.generateCertificate(domain, email)
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})
