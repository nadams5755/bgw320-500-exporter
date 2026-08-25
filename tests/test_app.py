import os
from pathlib import Path

from bs4 import BeautifulSoup

import app

FIXTURES = Path(__file__).parent / "fixtures"


def load(name):
    return BeautifulSoup((FIXTURES / name).read_text(), "html.parser")


def test_parse_uptime_str_plain_seconds():
    assert app.parse_uptime_str("57067") == 57067


def test_parse_uptime_str_legacy_colon_format():
    assert app.parse_uptime_str("1:02:03:04") == 24 * 60 * 60 + 2 * 3600 + 3 * 60 + 4


def test_parse_device_info():
    info = app.parse_device_info(load("sysinfo.html"))
    assert info == {
        "model_number": "BGW320-505",
        "serial_number": "F4KE00000001",
        "software_version": "6.35.8",
        "uptime": 57067,
    }


def test_parse_broadband_stats():
    stats = app.parse_broadband_stats(load("broadband.html"))
    assert stats == {
        "broadband_connection": "Up",
        "broadband_ip_address": "203.0.113.10",
        "broadband_ip6_address": "2001:db8::1",
        "receive_bytes": 20481376953,
        "receive_packets": 24434732,
        "transmit_bytes": 22202241496,
        "transmit_packets": 19151520,
    }


def test_optional_field_defaults_when_ipv6_unavailable():
    soup = BeautifulSoup("<table><tr><th>Status</th><td>Unavailable</td></tr></table>", "html.parser")
    assert app.optional_field(soup, "Global Unicast IPv6 Address") == ""


def test_parse_broadband_stats_prefers_ipv4_transmit_packets():
    # "Transmit Packets" appears in both the IPv4 and IPv6 Statistics
    # sections; the IPv4 value (first in document order) must win.
    stats = app.parse_broadband_stats(load("broadband.html"))
    assert stats["transmit_packets"] == 19151520
    assert stats["transmit_packets"] != 11


def test_parse_fiber_stats():
    fiber = app.parse_fiber_stats(load("fiberstat.html"))
    assert fiber["wan_up"] is True
    assert {m["name"] for m in fiber["metrics"]} == {
        "temperature",
        "vcc",
        "tx_bias",
        "tx_power",
        "rx_power",
    }

    temperature = next(m for m in fiber["metrics"] if m["name"] == "temperature")
    assert temperature["current"] == 42
    assert temperature["thresholds"]["alarm"]["low"] == (-50, False)
    assert temperature["thresholds"]["alarm"]["high"] == (95, False)
    assert temperature["thresholds"]["warning"]["low"] == (-45, False)
    assert temperature["thresholds"]["warning"]["high"] == (90, False)

    rx_power = next(m for m in fiber["metrics"] if m["name"] == "rx_power")
    assert rx_power["current"] == -188


def test_parse_lan_stats():
    ports = app.parse_lan_stats(load("lanstatistics.html"))
    assert [p["port"] for p in ports] == ["Port 1", "Port 2", "Port 3", "Port 4"]

    port1 = ports[0]
    assert port1["up"] is True
    assert port1["speed_bps"] == 5000000000
    assert port1["receive_bytes"] == 1047361343
    assert port1["receive_packets"] == 19595857
    assert port1["transmit_bytes"] == 85026562
    assert port1["transmit_packets"] == 25591757

    port2 = ports[1]
    assert port2["up"] is False
    assert port2["speed_bps"] == 0


def test_counter_from_label_returns_counter():
    # Regression test: the original counter_from_label built a
    # CounterMetricFamily but never returned it, so every call site yielded
    # None instead of a metric.
    counter = app.counter_from_label("receive_bytes_total", "Receive Bytes", 123)
    assert counter is not None
    samples = list(counter.samples)
    assert len(samples) == 1
    assert samples[0].value == 123


def test_collect_logs_and_skips_on_scrape_failure(monkeypatch, caplog):
    def fail(*args, **kwargs):
        raise app.requests.ConnectionError("boom")

    monkeypatch.setattr(app, "fetch_soup", fail)
    metrics = list(app.CustomCollector().collect())
    assert metrics == []
