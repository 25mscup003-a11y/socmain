# Current Architecture

    Agents ──signed/legacy HTTP──> Express monolith ──> MongoDB
      ^                                  │                 metadata
      │                                  ├─ in-process     logs
      └──── Socket.IO commands ──────────┤  detection      alerts
    Company/Superadmin React ─REST/WS──> ├─ SOAR/IPS
                                         └─ external APIs

## Runtime

- Express parses JSON and invokes route handlers directly.
- Python agents send alert batches of up to 20 from an in-memory priority queue.
- alert batches use Mongoose insertMany; generic logs support single/batch HTTP.
- live feeds use Socket.IO; one SSE log stream also exists.
- reports, correlation, heartbeat sweeps and IPS expiry run inside the API.
- production mode forks per CPU and uses custom IPC for Socket.IO. Database
  initialization/migrations still occur in worker startup.

## Deployment

No reproducible production deployment exists in the repository. Nginx files
are zero-byte and there are no Dockerfiles, Compose/Kubernetes resources,
network policies, probes, autoscaling policies or CI workflows.
