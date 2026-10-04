const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function isTransientStorageError(error) {
  return /Mongo(Network|ServerSelection|TopologyClosed|NotConnected|PoolCleared)|MongooseServerSelection|TimeoutError/.test(error?.name || '')
    || ['ECONNRESET', 'ECONNREFUSED', 'ETIMEDOUT', 'EAI_AGAIN', 'ENOTFOUND', 6, 7, 89, 91, 189, 262, 9001, 11600, 11602, 13435, 13436].includes(error?.code)
    || error?.hasErrorLabel?.('RetryableWriteError') === true
    || error?.hasErrorLabel?.('TransientTransactionError') === true
    || /before initial connection is complete|client must be connected|topology is closed/i.test(error?.message || '');
}

// Keep the offset in Kafka during a storage outage. Republishing immediately
// can exhaust all poison-message retries while the database is still offline.
async function persistWithStorageRetry(documents, {
  persist, heartbeat, isRunning = () => true, isStale = () => false,
  wait = sleep, logger = console,
}) {
  let attempts = 0;
  const keepAlive = async () => {
    try { await heartbeat(); } catch (error) {
      error.brokerControlError = true;
      throw error;
    }
  };
  while (isRunning() && !isStale()) {
    try {
      await persist(documents, { heartbeat: keepAlive });
      return true;
    } catch (error) {
      if (error.brokerControlError || !isTransientStorageError(error)) throw error;
      attempts += 1;
      const delayMs = Math.min(30_000, 1000 * 2 ** Math.min(attempts - 1, 5));
      logger.warn(JSON.stringify({ event: 'broker_storage_retry', attempt: attempts, delayMs, error: error.name }));
      for (let elapsed = 0; elapsed < delayMs && isRunning() && !isStale(); elapsed += 1000) {
        await keepAlive();
        await wait(Math.min(1000, delayMs - elapsed));
      }
    }
  }
  return false;
}

module.exports = { isTransientStorageError, persistWithStorageRetry };
