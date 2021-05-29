const Client = require('./lib/client')

const main = async function () {
  const client = new Client()

  await Promise.all([
    client.directory(),
    client.generateKeyPair()
  ])

  await client.newNonce()
  await client.newAccount('foo@bar.com')
  const { authzUrls, domains, finalizeUrl, orderUrl } = await client.newOrder('bar.com')
  const challenge = await client.authz(authzUrls[0])

  await client.respondChallenge(challenge)
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})
