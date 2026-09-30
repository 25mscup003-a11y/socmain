let sdk = null;

function startTelemetry() {
  if (process.env.OTEL_ENABLED !== 'true') return null;
  const { NodeSDK } = require('@opentelemetry/sdk-node');
  const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-http');
  const { HttpInstrumentation } = require('@opentelemetry/instrumentation-http');
  const { ExpressInstrumentation } = require('@opentelemetry/instrumentation-express');
  sdk = new NodeSDK({
    traceExporter: new OTLPTraceExporter({ url: process.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT }),
    instrumentations: [new HttpInstrumentation(), new ExpressInstrumentation()],
  });
  sdk.start();
  return sdk;
}

async function stopTelemetry() {
  if (sdk) await sdk.shutdown();
  sdk = null;
}

module.exports = { startTelemetry, stopTelemetry };
