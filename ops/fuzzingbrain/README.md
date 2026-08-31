# FuzzingBrain isolated runtime

This runtime is intentionally separate from the PentestGPT, Kong, and TRUDI
environments.

- Python lives in `third_party/fuzzingbrain/.venv`.
- Compose project `hunter-fuzzingbrain` owns dedicated MongoDB and Redis
  volumes.
- Services bind only to loopback, on ports `27018` and `6380` by default.
- No script edits `/etc/docker/daemon.json` or restarts the Docker daemon.

Bootstrap and verify:

```bash
scripts/fuzzingbrain_bootstrap.sh
scripts/fuzzingbrain_services.sh up
third_party/fuzzingbrain/.venv/bin/python scripts/fuzzingbrain_healthcheck.py
cd third_party/fuzzingbrain
.venv/bin/python -m pytest -q tests
```

Run the CLI through the launcher (it loads an optional patch module before
executing `fuzzingbrain.main` in the same interpreter):

```bash
third_party/fuzzingbrain/.venv/bin/python scripts/fuzzingbrain_run.py --help
FUZZINGBRAIN_PATCH_MODULE=fuzzingbrain_deepseek_adapter \
  third_party/fuzzingbrain/.venv/bin/python scripts/fuzzingbrain_run.py ...
```

Override host ports with `FUZZINGBRAIN_MONGO_PORT` and
`FUZZINGBRAIN_REDIS_PORT`; pass matching `MONGODB_URL` and `REDIS_URL` to a
task when overriding them.
