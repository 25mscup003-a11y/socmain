# soc-update

To set up the backend for local development:

```sh
cd backend
npm install
npm run setup:env
npm run dev
```

`setup:env` creates a private, Git-ignored `backend/.env` from
`backend/.env.example`, with separate random JWT and agent storage keys. It
preserves an existing `.env`. Keep those keys when restoring an existing setup.

Start MongoDB locally at `127.0.0.1:27017`, or set `MONGO_URI` in `backend/.env`
to your database connection string before starting the backend. The API uses
`http://localhost:5000`; company and superadmin apps use ports 3000 and 3001.
These settings are for local development; production requires its own secrets,
domains, and TLS configuration.
