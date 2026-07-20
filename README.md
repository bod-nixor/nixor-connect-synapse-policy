# Nixor Synapse Policy

This repository contains the upload-safe Synapse policy module and production configuration/cutover artifacts for Nixor Connect.

## Policy guarantees

- Every room, space, subspace, and room-in-space creation is classified and authorized by Panapticon.
- Panapticon denial, timeout, network failure, non-JSON output, or malformed output denies creation.
- Ambiguous or mismatched parent-space metadata is denied before the API call.
- Encrypted room creation and `m.room.encryption` events are blocked.
- Configuration is rejected at Synapse startup if fail-closed mode, endpoint, or authentication is unsafe.
- The callback uses Synapse's asynchronous HTTP client and never logs the shared secret or policy response body.

Synapse 1.132 or later is required because the supported `user_may_create_room` callback includes the room configuration. The inventoried public endpoint reports Synapse 1.156.0.

## Production configuration

Use [homeserver.yaml.example](homeserver.yaml.example) as a shape, not as a populated config. Production requires PostgreSQL, disabled public registration/password login, an immutable existing `server_name`, and a policy secret supplied through a protected absolute file path.

The policy URL may use HTTP only for loopback/private service hosts. Use HTTPS for any routable hostname. The endpoint must be `/internal/policy/check` and the secret must match Panapticon's `POLICY_SHARED_SECRET`.

Make the module importable before Synapse starts:

```sh
export PYTHONPATH=/path/to/nixor-connect-synapse-policy/modules
```

Then validate the protected real config in the Synapse virtualenv:

```sh
PYTHONPATH="$PWD/modules" /path/to/synapse/env/bin/python \
  ops/validate_production_config.py --config /protected/homeserver.yaml
```

## Verification

The unit suite uses only the Python standard library and test doubles for the stable Synapse module API:

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q modules ops tests
```

For the required SQLite-to-PostgreSQL rehearsal, count comparison, final cutover, and rollback sequence, follow [docs/postgresql-cutover.md](docs/postgresql-cutover.md).

Live Synapse databases, media, signing keys, logs, populated configs, secret files, count evidence, and snapshots must not be committed.
