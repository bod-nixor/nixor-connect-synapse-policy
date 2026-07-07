# Nixor Synapse Policy

This repository contains the upload-safe Synapse policy module and example configuration for Nixor Connect.

## Contents

- `modules/nixor_policy_checker.py` blocks encrypted room creation/events and asks Panapticon whether a Matrix user may create spaces or rooms.
- `homeserver.yaml.example` shows the Synapse module configuration with placeholder secrets.

## Local Runtime Files

Do not commit a live Synapse data directory. The real `homeserver.yaml`, SQLite database, media store, signing keys, logs, and Python caches are intentionally ignored.

## Example Module Config

```yaml
modules:
  - module: nixor_policy_checker.NixorPolicyChecker
    config:
      panapticon_api_url: "http://host.docker.internal:4000/internal/policy/check"
      policy_shared_secret: "replace-with-random-secret"
      fail_closed: true
```
