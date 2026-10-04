const test = require('node:test');
const assert = require('node:assert/strict');
const { persistWithStorageRetry } = require('../src/utils/brokerStorageRetry');

test('storage outage retains the batch until recovery and heartbeats during backoff', async () => {
  let attempts = 0;
  let heartbeats = 0;
  const waits = [];
  const documents = [{ eventId: 'same-on-retry' }];
  const result = await persistWithStorageRetry(documents, {
    persist: async batch => {
      assert.equal(batch, documents);
      if (++attempts < 3) throw Object.assign(new Error('offline'), { name: 'MongoNetworkError' });
    },
    heartbeat: async () => { heartbeats += 1; },
    wait: async ms => { waits.push(ms); },
    logger: { warn() {} },
  });
  assert.equal(result, true);
  assert.equal(attempts, 3);
  assert.equal(heartbeats, 3);
  assert.deepEqual(waits, [1000, 1000, 1000]);
});

test('invalid data reaches poison-message handling without indefinite retries', async () => {
  const error = Object.assign(new Error('invalid tenant'), { name: 'ValidationError' });
  await assert.rejects(persistWithStorageRetry([], {
    persist: async () => { throw error; }, heartbeat: async () => {},
  }), error);
});

test('rebalance or shutdown stops retrying without marking the batch persisted', async () => {
  let stale = false;
  let attempts = 0;
  const result = await persistWithStorageRetry([], {
    persist: async () => { attempts += 1; throw Object.assign(new Error('offline'), { code: 'ECONNREFUSED' }); },
    heartbeat: async () => {}, wait: async () => { stale = true; },
    isStale: () => stale, logger: { warn() {} },
  });
  assert.equal(result, false);
  assert.equal(attempts, 1);
});

test('heartbeat failures remain consumer errors instead of poison records', async () => {
  const failure = new Error('group rebalancing');
  await assert.rejects(persistWithStorageRetry([], {
    persist: async (_documents, { heartbeat }) => heartbeat(),
    heartbeat: async () => { throw failure; },
  }), error => error === failure && error.brokerControlError === true);
});
