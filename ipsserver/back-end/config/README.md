# Configuration Files

This directory contains configuration settings for the IPS Webhook Server.

## Files

- `.env` — Environment variables (port, auth secret, MongoDB)

## Configuration Options

### IPS_WEBHOOK_PORT
- **Type**: Number
- **Default**: 5050
- **Description**: Port the webhook server listens on

### IPS_WEBHOOK_SECRET
- **Type**: String
- **Default**: (empty - no authentication)
- **Description**: Optional authentication secret. If set, requests must include header: `X-Webhook-Secret: <value>`

### Runtime logs
- Stored in the MongoDB `soc4_ips.ips_logs` collection
- No filesystem log directory is created

### NODE_ENV
- **Type**: String
- **Default**: production
- **Options**: production, development
- **Description**: Node environment mode
