#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/../.." && pwd)"
BACKEND_ENV="$ROOT_DIR/backend/.env"

[[ -f "$BACKEND_ENV" ]] || { echo "Missing backend environment file: $BACKEND_ENV" >&2; exit 1; }

declare -A desired=(
  [INGESTION_MODE]="broker"
  [KAFKA_BROKERS]="localhost:19092"
  [KAFKA_CLIENT_ID]="ajnat-ingestion-local"
  [KAFKA_ALERT_GROUP_ID]="soc-alert-storage-v1"
  [KAFKA_ALERT_PARTITIONS]="6"
  [KAFKA_REPLICATION_FACTOR]="1"
  [KAFKA_CONSUMER_PARTITION_CONCURRENCY]="3"
  [KAFKA_CONSUMER_MAX_PARTITION_BYTES]="5242880"
  [KAFKA_CONNECTION_TIMEOUT_MS]="10000"
  [KAFKA_REQUEST_TIMEOUT_MS]="30000"
  [BROKER_ALERT_TOPIC]="soc.alerts.v1"
  [BROKER_ALERT_RETRY_TOPIC]="soc.alerts.retry.v1"
  [BROKER_ALERT_DLQ_TOPIC]="soc.alerts.dlq.v1"
  [BROKER_MAX_RETRIES]="8"
  [BROKER_CORRELATION_DEBOUNCE_MS]="30000"
  [BROKER_SOAR_CONCURRENCY]="8"
)

BACKUP_DIR="$ROOT_DIR/backend/.runtime-secrets/config-backups"
mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
backup="$BACKUP_DIR/backend.env.$(date +%Y%m%d%H%M%S)"
cp --preserve=mode "$BACKEND_ENV" "$backup"

for key in "${!desired[@]}"; do
  value="${desired[$key]}"
  if grep -qE "^${key}=" "$BACKEND_ENV"; then
    sed -i -E "s|^${key}=.*$|${key}=${value}|" "$BACKEND_ENV"
  else
    printf '%s=%s\n' "$key" "$value" >> "$BACKEND_ENV"
  fi
done

echo "Backend Kafka settings configured. Backup: $backup"
echo "Restart the backend so the producer and ingestion worker use the new settings."
