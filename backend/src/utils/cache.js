/**
 * cache.js
 * A simple, high-performance in-memory cache helper with TTL support.
 */
class SimpleMemoryCache {
  constructor() {
    this.cache = new Map();
  }

  /**
   * Get an item from the cache.
   * @param {string} key 
   * @returns {*} cached value or null if expired/not found
   */
  get(key) {
    const entry = this.cache.get(key);
    if (!entry) return null;

    if (entry.expiresAt && Date.now() > entry.expiresAt) {
      this.cache.delete(key);
      return null;
    }

    return entry.value;
  }

  /**
   * Set an item in the cache.
   * @param {string} key 
   * @param {*} value 
   * @param {number} ttlSeconds 
   */
  set(key, value, ttlSeconds = 60) {
    const expiresAt = ttlSeconds > 0 ? Date.now() + (ttlSeconds * 1000) : null;
    this.cache.set(key, { value, expiresAt });
  }

  /**
   * Delete an item from the cache.
   * @param {string} key 
   */
  delete(key) {
    this.cache.delete(key);
  }

  /**
   * Clear all items from the cache.
   */
  clear() {
    this.cache.clear();
  }
}

// Global default cache instance
const defaultCache = new SimpleMemoryCache();

module.exports = {
  SimpleMemoryCache,
  defaultCache
};
