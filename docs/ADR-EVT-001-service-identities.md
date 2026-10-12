# ADR-EVT-001: event service identities issued by Security

Status: accepted for local development; runtime transport remains pending.

Security alone signs machine credentials. Issue-EventServiceToken.ps1 is an
operator-only PowerShell 7 command, not a public registration endpoint. Its
administrator must already have access to Security's private key. Workflow's
existing issuer remains unchanged.

| Service | Audience | Roles | Public credential destination |
| --- | --- | --- | --- |
| mis-worker | mis-api | INVENTORY | mis-worker/secrets/ENV/mis-worker |
| mis-inventory-relay | mis-events | none | mis-inventory-api/secrets/ENV/mis-inventory-relay |

The operator supplies a canonical, nonzero UUID and explicitly registers it
once with -Register. Security records service, environment, subject, audience
and key ID under its ignored secrets directory. Renewal cannot replace that
identity, even with -Register. Subjects cannot be reused across registered
services/environments, including Workflow. Identity/key rotation requires a
separate reviewed operation; deleting registries is not a renewal procedure.

Example from a Security checkout with configured env/dev.env and RSA keys:

```powershell
./scripts/Issue-EventServiceToken.ps1 -Service mis-worker -Subject '<stable-worker-uuid>' -Environment dev -Register
./scripts/Issue-EventServiceToken.ps1 -Service mis-inventory-relay -Subject '<distinct-relay-uuid>' -Environment dev -Register
```

Omit -Register to renew the same subject. TTL is 60..3600 seconds. Tokens are
atomically replaced; jti changes on renewal. Consumers receive only public.pem
and service.jwt, never private keys. Existing foreign public keys fail closed.
The issuer validates the RSA pair before recording a new identity. Credentials
are local ignored files: restrict their directory to the operator/container
account using host ACLs (or owner-only Unix permissions); do not upload them.

This does not provide automatic rotation, revocation, remote OAuth issuance,
or concurrent administrative registration. Run one issuer per identity at a
time. Public key publication and registry persistence are not one filesystem
transaction; retry with the same subject after an interrupted first issue.

Tests use disposable synthetic RSA pairs for all three environments, verify
signatures and claims, preserve JWTs on rejection, and reject subject reuse.
They do not assert live Worker/relay authorization or end-to-end delivery.
