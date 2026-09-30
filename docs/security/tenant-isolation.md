# Tenant Isolation

## Invariants

1. Tenant, partner, company, department and system scope comes from the
   authenticated principal and authoritative records.
2. Payload scope fields are assertions only; mismatch is rejected.
3. Partner admins access only their partner's companies.
4. Company users cannot select another company in body/query/path.
5. Department users are restricted to assigned departments.
6. Cache, queue, idempotency and export keys include tenant/company scope.
7. Superadmin access is explicit and audited.

## Current

scopeForUser, resolveScope and assertIncomingScope provide application filtering.
Socket rooms now apply resource checks. This is not a database-enforced boundary;
route omissions remain possible.

## Target

- transactional database row policies or a mandatory scoped repository layer.
- ClickHouse query service injects tenant predicate, time/scan/result limits and
  tenant quotas.
- object storage uses server-generated prefixes and scoped signed URLs.
- stream envelopes receive scope from authenticated enrollment, never payload.

Every tenant route needs a negative test proving another tenant ID returns
404/403 without revealing resource existence.
