# Synapse SQLite-to-PostgreSQL cutover

Production activation is blocked until the live Synapse database is confirmed as PostgreSQL. The preserved local development copy is SQLite schema `94:1`; it must never be treated as the production source of truth.

This runbook follows Synapse's supported, repeatable `synapse_port_db` process. Never copy or mutate Synapse tables manually. See the official [PostgreSQL migration guide](https://element-hq.github.io/synapse/latest/postgres.html) and [backup guide](https://element-hq.github.io/synapse/latest/usage/administration/backups.html).

## Preconditions

1. Obtain authenticated access to the live host and confirm the active config, Synapse version, database engine, service manager, disk headroom, and maintenance owner.
2. Freeze the policy/config artifact SHA and record the exact Synapse package version.
3. Provision a least-privilege PostgreSQL role and database using `UTF8`, `LC_COLLATE='C'`, `LC_CTYPE='C'`, and `TEMPLATE=template0`. Do not set `allow_unsafe_locale`.
4. Install the PostgreSQL dependency in the same virtualenv that runs Synapse.
5. Create a protected PostgreSQL config copied from the live config. Change only the database block and the reviewed release settings. Do not change the immutable `server_name`, signing key, media path, or secrets.
6. Validate the real config:

   ```sh
   PYTHONPATH=/path/to/release/modules /path/to/synapse/env/bin/python \
     ops/validate_production_config.py --config /protected/homeserver-postgres.yaml
   ```

## Rehearsal while production remains online

1. Take a crash-consistent copy of the SQLite database and immutable checksums of the snapshot, live config, signing key, and a media inventory. Store them outside the live data directory.
2. Capture the baseline without exposing connection settings:

   ```sh
   /path/to/synapse/env/bin/python ops/synapse_db_counts.py \
     --config /protected/homeserver-snapshot.yaml \
     --sqlite-database /protected/homeserver.db.snapshot \
     --output /protected/rehearsal-sqlite.counts.json
   ```

3. Port the snapshot into an empty rehearsal PostgreSQL database:

   ```sh
   /path/to/synapse/env/bin/synapse_port_db \
     --sqlite-database /protected/homeserver.db.snapshot \
     --postgres-config /protected/homeserver-postgres-rehearsal.yaml
   ```

4. Capture and compare PostgreSQL counts. The command exits nonzero on any user, room, device, event, or local-media count mismatch:

   ```sh
   /path/to/synapse/env/bin/python ops/synapse_db_counts.py \
     --config /protected/homeserver-postgres-rehearsal.yaml \
     --compare /protected/rehearsal-sqlite.counts.json \
     --output /protected/rehearsal-postgres.counts.json
   ```

5. Record port duration and database/media disk use. Start an isolated rehearsal Synapse using copied signing/config/media artifacts and non-public listeners. Verify versions, login-token login, sync, room message, media read/write, admin APIs, the policy module's allowed and denied creation cases, and encryption denial.
6. Destroy only the explicitly named rehearsal instance after evidence is retained.

## Final cutover

1. Announce the approved maintenance window and stop all Synapse writers. Confirm the process and listener are stopped.
2. Take a final immutable SQLite/config/signing-key/media backup and record checksums. Capture final SQLite counts.
3. Rerun `synapse_port_db` against the final live SQLite file and the already-rehearsed PostgreSQL target. The tool is resumable; do not improvise another conversion path.
4. Compare the five critical counts and investigate every mismatch before starting Synapse.
5. Point the protected production config at PostgreSQL, validate it, set `PYTHONPATH` to this release's `modules` directory, and start one monolith Synapse instance.
6. Verify `/_matrix/client/versions`, Google-to-login-token authentication, sync, DM and governed room messaging, media, admin APIs, unauthorized space denial, allowed managed creation, Panapticon-unavailable denial, and encryption denial. Record correlation IDs and timings without recording tokens or private content.

## Rollback

Application rollback is allowed only before new writes are accepted on PostgreSQL, or by an incident decision with a documented reverse-data plan. For an immediate failed-start cutover: stop Synapse, restore the exact pre-cutover config, retain the failed PostgreSQL database for investigation, restore the immutable SQLite/media/config/signing-key set if needed, start the prior artifact, and rerun login/sync/message/media checks. Never point two Synapse writers at SQLite and PostgreSQL simultaneously.
