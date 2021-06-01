const crypto = require('crypto')

const PRIVATE_KEY_CIPHER = 'aes-256-cbc'
const PRIVATE_KEY_FORMAT = 'pem'
const PRIVATE_KEY_TYPE = 'pkcs1'

const PUBLIC_KEY_FORMAT = 'pem'
const PUBLIC_KEY_TYPE = 'pkcs1'

/**
 * @param  {crypto.KeyObject} privateKey
 * @param  {String}           [passphrase]
 *
 * @return {String}
 */
const exportPrivateKey = (privateKey, passphrase) => {
  const privateKeyOpts = {
    type: PRIVATE_KEY_TYPE,
    format: PRIVATE_KEY_FORMAT
  }

  if (passphrase) {
    privateKeyOpts.cipher = PRIVATE_KEY_CIPHER
    privateKeyOpts.passphrase = passphrase
  }

  return privateKey.export(privateKeyOpts)
}

/**
 * @param  {crypto.KeyObject} publicKey
 *
 * @return {String}
 */
const exportPublicKey = publicKey => {
  return publicKey.export({
    type: PUBLIC_KEY_TYPE,
    format: PUBLIC_KEY_FORMAT
  })
}

/**
 * @param  {String} privateKeyData
 * @param  {String} [passphrase]
 *
 * @return {String}
 */
const importPrivateKey = (privateKeyData, passphrase) => {
  const privateKeyOpts = {
    key: privateKeyData,
    format: PRIVATE_KEY_FORMAT,
    type: PRIVATE_KEY_TYPE
  }

  if (passphrase) {
    privateKeyOpts.passphrase = passphrase
  }

  try {
    return crypto.createPrivateKey(privateKeyOpts)
  } catch {
    throw new Error('Failed to import private key')
  }
}

/**
 * @param  {String} publicKeyData
 *
 * @return {crypto.KeyObject}
 */
const importPublicKey = publicKeyData => {
  try {
    return crypto.createPublicKey({
      key: publicKeyData,
      format: PUBLIC_KEY_FORMAT,
      type: PUBLIC_KEY_TYPE
    })
  } catch {
    throw new Error('Failed to import public key')
  }
}

module.exports = {
  PRIVATE_KEY_CIPHER,
  PRIVATE_KEY_FORMAT,
  PRIVATE_KEY_TYPE,
  PUBLIC_KEY_FORMAT,
  PUBLIC_KEY_TYPE,
  exportPrivateKey,
  exportPublicKey,
  importPrivateKey,
  importPublicKey
}
