const https = require('https')

/**
 * @param  {String}    url          [description]
 * @param  {String}    options.data [description]
 * @param  {...[type]} options.opts [description]
 *
 * @return {Promise}
 */
const request = (url, { data = '', ...opts } = {}) => {
  return new Promise((resolve, reject) => {
    try {
      url = new URL(url)
    } catch (err) {
      return reject(err)
    }

    https.request(url, opts, res => {
      const { statusCode, headers } = res

      let data = ''

      res
        .on('data', chunk => {
          data += chunk
        })
        .once('end', () => resolve({ data, headers, statusCode }))
        .once('error', reject)
    })
      .once('error', reject)
      .end(data)
  })
}

module.exports = {
  request
}
