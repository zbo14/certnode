const https = require('https')

/**
 * @param  {String}  url
 * @param  {Object}  [options = {}]
 * @param  {String}  [options.data = '']
 * @param  {...*}    [options.opts]
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
        .once('end', () => {
          if (headers['content-type']?.includes('application/json')) {
            try {
              data = JSON.parse(data)
            } catch (err) {
              reject(err)
              return
            }
          }

          resolve({ data, headers, statusCode })
        })
        .once('error', reject)
    })
      .once('error', reject)
      .end(data)
  })
}

module.exports = {
  request
}
