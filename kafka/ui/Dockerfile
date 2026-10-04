ARG KAFKA_UI_IMAGE=kafbat/kafka-ui:v1.5.0
FROM ${KAFKA_UI_IMAGE} AS upstream

FROM python:3.13-alpine AS customize
COPY --from=upstream /api.jar /upstream/api.jar
COPY hide-social-links.py /hide-social-links.py
COPY topic-acls.js /topic-acls.js
RUN python /hide-social-links.py /upstream/api.jar /api.jar

FROM upstream
COPY --from=customize --chown=kafkaui:kafkaui /api.jar /api.jar
