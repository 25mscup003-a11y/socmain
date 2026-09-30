# High-scale SOC deployment

The `high` scale profile is intended for roughly 10–20k reporting agents and large concurrent dashboard traffic. It deliberately refuses to start unless durable ingestion, distributed sockets, and analytical storage are configured.

## Required production profile

```env
NODE_ENV=production
SCALE_PROFILE=high

CLUSTER_MODE=true
WEB_CONCURRENCY=8

INGESTION_MODE=broker
KAFKA_BROKERS=kafka-1:9092,kafka-2:9092,kafka-3:9092
KAFKA_CONSUMER_PARTITION_CONCURRENCY=6

HOT_EVENT_STORE=dual

SOCKET_ADAPTER=redis
REDIS_URL=redis://redis:6379
READ_CACHE_REDIS_ENABLED=true

MONGO_MAX_POOL_SIZE=40
MONGO_MIN_POOL_SIZE=5
MONGO_MAX_CONNECTING=4
MONGO_WAIT_QUEUE_TIMEOUT_MS=5000
MONGO_AUTO_INDEX=false
```

Run multiple API nodes behind a WebSocket-capable load balancer. Because the clients use WebSocket-only Socket.IO and the Redis adapter, sticky sessions are not required. The total MongoDB connection budget is `API nodes × WEB_CONCURRENCY × MONGO_MAX_POOL_SIZE`; size it against the database limit rather than increasing it blindly.

Kafka topics should have enough partitions for the desired ingestion concurrency. Run `worker:alerts` separately from API processes. Use ClickHouse for hot event analytics and retain MongoDB for operational records; `dual` mode supports a staged migration.

## Request protection included in the application

- Tenant/role/user-aware Redis + bounded memory caching for expensive dashboards.
- In-process request coalescing prevents a cache stampede per API worker.
- A concurrency ceiling returns `503` with `Retry-After` instead of exhausting MongoDB.
- Browser GET deduplication, session-isolated cache keys, hidden-tab suppression, and 60-second polling fallback.
- Redis-backed Socket.IO fan-out and WebSocket-only transport.
- Bounded MongoDB wait queues and connection creation.
- Coalesced subscription/USB-policy lookups and no empty command write on every agent heartbeat.

Tune `READ_CACHE_MAX_CONCURRENT_MISSES`, `READ_CACHE_MAX_ENTRIES`, cache TTLs, pool sizes, worker count, and Kafka partitions from `/metrics` latency/error data. Build production indexes in a controlled migration before setting `MONGO_AUTO_INDEX=false`.
