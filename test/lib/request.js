const assert = require('assert')
const fakeTimers = require('@sinonjs/fake-timers')
const request = require('../../lib/request')

describe('lib/request', () => {
  beforeEach(() => {
    this.clock = fakeTimers.install()
  })

  afterEach(() => {
    this.clock.uninstall()
  })

  it('times out', async () => {
    try {
      await request('https://some.where', { method: 'POST' }, () => {
        this.clock.tick(10e3)
      })

      assert.fail('Should reject')
    } catch ({ message }) {
      assert.strictEqual(message, 'POST request to "https://some.where/" timed out')
    }
  })
})
