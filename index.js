const Client = require('./lib/client')

const main = async function () {
  const { domain, email } = process.env
  const client = new Client()

  await Promise.all([
    client.directory(),
    client.generateKeyPair()
  ])

  await client.newNonce()
  await client.newAccount(email)
  const { authzUrls } = await client.newOrder(domain)
  const { challenge } = await client.authz(authzUrls[0])

  await client.respondChallenge(challenge)
  const result = await client.authz(authzUrls[0])
  console.log(result)
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})
