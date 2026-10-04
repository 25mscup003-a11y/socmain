#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
KAFKA_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
COMPOSE_FILE="$KAFKA_DIR/docker-compose.yml"
ENV_FILE="$KAFKA_DIR/.env"

# Parse dotenv without executing it as shell code. Use the same settings for
# Compose, status/lag commands, and the backend configuration helper.
config_values="$(node "$SCRIPT_DIR/local-config.js")"
while IFS='=' read -r key value; do
  export "$key=$value"
done <<< "$config_values"

# Compose validates env_file paths even for inactive profiles. Bootstrap the
# private UI login once so a fresh checkout can run `up` without enabling tools.
node "$SCRIPT_DIR/setup-ui.js" >/dev/null

compose() {
  if [[ -f "$ENV_FILE" ]]; then
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" "$@"
  else
    docker compose -f "$COMPOSE_FILE" "$@"
  fi
}

wait_for_kafka() {
  local attempts=36
  until kafka_cli kafka-broker-api-versions --bootstrap-server kafka:9092 >/dev/null 2>&1; do
    attempts=$((attempts - 1))
    if (( attempts == 0 )); then
      echo "Kafka did not become ready. Run: $0 logs" >&2
      return 1
    fi
    sleep 5
  done
}

kafka_cli() {
  # Admin CLIs must not try to bind the broker JVM's JMX port.
  compose exec -T -e KAFKA_JMX_OPTS= -e JMX_PORT= kafka "$@"
}

provision_topics() {
  compose up -d kafka-init >/dev/null
  local attempts=30 status exit_code
  while (( attempts > 0 )); do
    status="$(docker inspect --format '{{.State.Status}}' soc-kafka-init 2>/dev/null || true)"
    if [[ "$status" == "exited" ]]; then
      exit_code="$(docker inspect --format '{{.State.ExitCode}}' soc-kafka-init 2>/dev/null || echo 1)"
      if [[ "$exit_code" == "0" ]]; then
        echo "AJNAT Kafka topics are ready."
        return 0
      fi
      echo "Kafka topic provisioning failed:" >&2
      compose logs --tail=100 kafka-init >&2
      return 1
    fi
    attempts=$((attempts - 1))
    sleep 1
  done
  echo "Kafka topic provisioning timed out:" >&2
  compose logs --tail=100 kafka-init >&2
  return 1
}

command="${1:-help}"
case "$command" in
  up)
    compose up -d kafka
    wait_for_kafka
    provision_topics
    echo "AJNAT Kafka is ready on localhost:${KAFKA_HOST_PORT:-19092}"
    ;;
  tools)
    node "$SCRIPT_DIR/setup-ui.js"
    compose --profile tools up -d --build kafka kafka-ui kafka-exporter
    # Reload the read-only SMTP mount after setup-ui synchronizes its contents.
    compose --profile tools up -d --build --no-deps --force-recreate kafka-ui-auth
    wait_for_kafka
    provision_topics
    echo "Kafka UI: http://localhost:${KAFKA_UI_HOST_PORT:-18080}"
    echo "Kafka metrics: http://localhost:${KAFKA_EXPORTER_HOST_PORT:-19308}/metrics"
    ;;
  down)
    compose --profile tools down
    ;;
  restart)
    compose restart kafka
    wait_for_kafka
    provision_topics
    ;;
  status)
    compose ps
    "$0" health
    ;;
  logs)
    compose logs --tail=200 -f kafka
    ;;
  topics)
    wait_for_kafka
    kafka_cli kafka-topics --bootstrap-server kafka:9092 --list
    ;;
  describe)
    wait_for_kafka
    kafka_cli kafka-topics --bootstrap-server kafka:9092 --describe
    ;;
  groups)
    wait_for_kafka
    kafka_cli kafka-consumer-groups --bootstrap-server kafka:9092 --list
    ;;
  lag)
    wait_for_kafka
    kafka_cli kafka-consumer-groups --bootstrap-server kafka:9092 \
      --describe --group "${KAFKA_ALERT_GROUP_ID:-soc-alert-storage-v1}"
    ;;
  health)
    wait_for_kafka
    required_topics=(
      "${BROKER_ALERT_TOPIC:-soc.alerts.v1}"
      "${BROKER_ALERT_RETRY_TOPIC:-soc.alerts.retry.v1}"
      "${BROKER_ALERT_DLQ_TOPIC:-soc.alerts.dlq.v1}"
      "${KAFKA_HEALTH_TOPIC:-soc.health.v1}"
    )
    topic_list="$(kafka_cli kafka-topics --bootstrap-server kafka:9092 --list)"
    for topic in "${required_topics[@]}"; do
      if ! grep -Fxq "$topic" <<<"$topic_list"; then
        echo "Missing required topic: $topic" >&2
        exit 1
      fi
    done
    echo "Kafka healthy; all AJNAT topics exist."
    ;;
  smoke)
    node --disable-warning=TimeoutNegativeWarning "$SCRIPT_DIR/smoke-test.js"
    ;;
  benchmark)
    node --disable-warning=TimeoutNegativeWarning "$SCRIPT_DIR/benchmark.js"
    ;;
  verify-ui)
    node "$SCRIPT_DIR/verify-ui.js"
    ;;
  reset)
    read -r -p "Delete the AJNAT Kafka containers AND all persisted Kafka data? Type DELETE: " answer
    [[ "$answer" == "DELETE" ]] || { echo "Cancelled."; exit 1; }
    compose --profile tools down --volumes
    echo "Kafka containers and volume removed."
    ;;
  help|*)
    cat <<'EOF'
Usage: ./scripts/manage.sh COMMAND

  up        Start Kafka and create required topics
  tools     Start Kafka plus local UI and Prometheus exporter
  status    Show containers and verify required topics
  logs      Follow Kafka logs
  topics    List topics
  describe  Describe topics and partitions
  groups    List consumer groups
  lag       Show AJNAT alert worker lag
  health    Verify the broker and required topics
  smoke     Verify publish/consume on the isolated health topic
  verify-ui Verify UI login, cluster, topics, groups and metrics
  benchmark Run a bounded broker-only check with 30000 logical agents
  restart   Restart Kafka and re-run topic provisioning
  down      Stop containers without deleting data
  reset     Delete containers and Kafka data (confirmation required)
EOF
    ;;
esac
