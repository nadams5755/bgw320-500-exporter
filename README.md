# Prometheus exporter for BGW320-500 routers

This exporter scrapes the UI pages of a BGW320-500 router to provide
some network and fiber optics metrics for Prometheus.

## Setup

Use a virtualenv for development and running the exporter:

```sh
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Run it:

```sh
ROUTER_ADDR=192.168.1.254 python app.py
```

Environment variables:

- `ROUTER_ADDR` — hostname/IP of the router (default `dsldevice.attlocal.net`)
- `ADDR` — address to bind the metrics HTTP server to (default `0.0.0.0`)
- `PORT` — port to bind the metrics HTTP server to (default `8000`)
- `ACCESSCODE` — the router's Device Access Code, needed to collect firewall/NAT
  connection stats (`connection_sessions_available`, `connection_sessions_in_use`,
  `connections`). If unset, these metrics are skipped and everything else
  is collected as normal.

`ACCESSCODE` is sensitive, so keep it out of your shell history and out of
version control. A `.credentials` file (gitignored) is a convenient place to
store it:

```sh
# .credentials
ACCESSCODE="your-access-code"
```

```sh
set -a && source .credentials && set +a
ROUTER_ADDR=192.168.1.254 python app.py
```

Metrics are then available at `http://localhost:8000/metrics`.

## Development

Install test dependencies and run the test suite:

```sh
pip install -r requirements-dev.txt
pytest
```

Tests run against sanitized HTML fixtures in `tests/fixtures/` captured from
a real router, so they don't require network access to a live device.
