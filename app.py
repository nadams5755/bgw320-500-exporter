"""bgw320-500 exporter"""
from collections import Counter
import hashlib
import logging
import os
import re
import time

from bs4 import BeautifulSoup
from prometheus_client import start_http_server
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily, REGISTRY
import requests


ROUTER_ADDR = os.getenv("ROUTER_ADDR", "dsldevice.attlocal.net")
ACCESSCODE = os.getenv("ACCESSCODE")

NONCE_RE = re.compile(r'name="nonce" value="([0-9a-f]+)"')

CURRENTLY_RE = re.compile(r"^(?P<name>.+?)\s*Currently\s*(?P<value>-?\d+)$")
THRESHOLD_CELL_RE = re.compile(r"(?P<crossed>-?\d+)\s*\(Threshold\s*(?P<threshold>-?\d+)\)")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def parse_uptime_str(uptime_str: str) -> int:
    uptime_str = uptime_str.strip()
    if ":" not in uptime_str:
        return int(uptime_str)

    split_str = uptime_str.split(":")
    return (
        int(split_str[3])
        + 60 * int(split_str[2])
        + 60 * 60 * int(split_str[1])
        + 24 * 60 * 60 * int(split_str[0])
    )


def field(soup, label):
    return soup.find("th", string=label).find_next_sibling("td").string.strip()


def optional_field(soup, label, default=""):
    th = soup.find("th", string=label)
    if th is None:
        return default
    return th.find_next_sibling("td").string.strip()


def fetch_soup(path):
    req = requests.get(f"http://{ROUTER_ADDR}{path}", timeout=15)
    req.raise_for_status()
    return BeautifulSoup(req.text, "html.parser")


_session = requests.Session()


def login():
    """Authenticate _session against the router's access-code login form.

    The login form's nonce is only present once the router has already set
    a session cookie, so the first request just establishes the cookie and
    the second one carries the actual form.
    """
    nonce = None
    for _ in range(2):
        resp = _session.get(f"http://{ROUTER_ADDR}/cgi-bin/routerpasswd.ha", timeout=15)
        resp.raise_for_status()
        match = NONCE_RE.search(resp.text)
        if match:
            nonce = match.group(1)
            break
    if nonce is None:
        raise RuntimeError("Could not find login nonce on routerpasswd.ha")

    hashpassword = hashlib.md5((ACCESSCODE + nonce).encode()).hexdigest()
    resp = _session.post(
        f"http://{ROUTER_ADDR}/cgi-bin/login.ha",
        data={
            "nonce": nonce,
            "password": "*" * len(ACCESSCODE),
            "hashpassword": hashpassword,
            "Continue": "Continue",
        },
        timeout=15,
    )
    resp.raise_for_status()


def fetch_authenticated_soup(path):
    resp = _session.get(f"http://{ROUTER_ADDR}{path}", timeout=15)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")

    if soup.title is not None and soup.title.string == "Login":
        login()
        resp = _session.get(f"http://{ROUTER_ADDR}{path}", timeout=15)
        resp.raise_for_status()
        soup = BeautifulSoup(resp.text, "html.parser")

    return soup


def parse_device_info(soup):
    return {
        "model_number": field(soup, "Model Number"),
        "serial_number": field(soup, "Serial Number"),
        "software_version": field(soup, "Software Version"),
        "uptime": parse_uptime_str(field(soup, "Time Since Last Reboot")),
    }


def parse_broadband_stats(soup):
    return {
        "broadband_connection": field(soup, "Broadband Connection"),
        "broadband_ip_address": field(soup, "Broadband IPv4 Address"),
        "broadband_ip6_address": optional_field(soup, "Global Unicast IPv6 Address"),
        "receive_bytes": int(field(soup, "Receive Bytes")),
        "receive_packets": int(field(soup, "Receive Packets")),
        "transmit_bytes": int(field(soup, "Transmit Bytes")),
        "transmit_packets": int(field(soup, "Transmit Packets")),
    }


def parse_fiber_stats(soup):
    metrics = []
    for h1 in soup.find_all("h1"):
        text = re.sub(r"\s+", " ", h1.get_text(" ", strip=True))
        match = CURRENTLY_RE.match(text)
        if not match:
            continue

        table = h1.find_next("table")
        thresholds = {}
        for row in table.find("tbody").find_all("tr"):
            cells = row.find_all("td")
            level = cells[0].get_text(strip=True).lower()
            low = THRESHOLD_CELL_RE.search(cells[1].get_text())
            high = THRESHOLD_CELL_RE.search(cells[2].get_text())
            thresholds[level] = {
                "low": (int(low["threshold"]), bool(int(low["crossed"]))),
                "high": (int(high["threshold"]), bool(int(high["crossed"]))),
            }

        name = match["name"].strip().lower().replace(" ", "_")
        metrics.append(
            {"name": name, "current": int(match["value"]), "thresholds": thresholds}
        )

    return {
        "wan_up": field(soup, "Optical WAN Operational Status") == "Up",
        "metrics": metrics,
    }


def parse_lan_stats(soup):
    table = soup.find("table", summary="LAN Ethernet Statistics Table")
    ports = [th.get_text(strip=True) for th in table.find("tr").find_all("th")[1:]]

    rows = {}
    for row in table.find_all("tr")[1:]:
        cells = row.find_all("td")
        rows[cells[0].get_text(strip=True)] = [c.get_text(strip=True) for c in cells[1:]]

    return [
        {
            "port": port,
            "up": rows["State"][i] == "up",
            "speed_bps": int(rows["Transmit Speed"][i]),
            "receive_bytes": int(rows["Receive Bytes"][i]),
            "receive_packets": int(rows["Receive Packets"][i]),
            "transmit_bytes": int(rows["Transmit Bytes"][i]),
            "transmit_packets": int(rows["Transmit Packets"][i]),
        }
        for i, port in enumerate(ports)
    ]


def parse_nat_stats(soup):
    table = soup.find("table", summary="Summary of nattable connections")

    connections = Counter()
    for row in table.find("tbody").find_all("tr"):
        cells = row.find_all("td")
        ip_family = cells[0].get_text(strip=True)
        protocol = cells[1].get_text(strip=True)
        tcp_state = cells[4].get_text(strip=True).replace("\xa0", "")
        connections[(ip_family, protocol, tcp_state)] += 1

    return {
        "sessions_available": int(field(soup, "Total sessions available")),
        "sessions_in_use": int(field(soup, "Total sessions in use")),
        "connections": connections,
    }


def counter_from_label(help_text, label, value):
    counter = CounterMetricFamily(help_text, label)
    counter.add_metric([], value)
    return counter


class CustomCollector:
    def describe(self):
        # Prevents prometheus_client from calling collect() once at
        # registration time (which would hit the network) just to learn
        # metric names.
        return []

    def collect(self):
        try:
            info = parse_device_info(fetch_soup("/cgi-bin/sysinfo.ha"))
            broadband = parse_broadband_stats(fetch_soup("/cgi-bin/broadbandstatistics.ha"))
            fiber = parse_fiber_stats(fetch_soup("/cgi-bin/fiberstat.ha"))
            lan_ports = parse_lan_stats(fetch_soup("/cgi-bin/lanstatistics.ha"))
            nat = (
                parse_nat_stats(fetch_authenticated_soup("/cgi-bin/nattable.ha"))
                if ACCESSCODE
                else None
            )
        except (requests.RequestException, AttributeError, ValueError, RuntimeError) as exc:
            logger.error("Failed to scrape %s: %s", ROUTER_ADDR, exc)
            return

        labels = [
            "model_number",
            "serial_number",
            "software_version",
            "ip_address",
            "ip6_address",
        ]
        label_values = [
            info["model_number"],
            info["serial_number"],
            info["software_version"],
            broadband["broadband_ip_address"],
            broadband["broadband_ip6_address"],
        ]

        gauge = GaugeMetricFamily("broadband_up", "Broadband is up", labels=labels)
        gauge.add_metric(label_values, 1 if broadband["broadband_connection"] == "Up" else 0)
        yield gauge

        yield counter_from_label("uptime_total", "Uptime in seconds", info["uptime"])
        yield counter_from_label(
            "receive_bytes_total", "Receive Bytes", broadband["receive_bytes"]
        )
        yield counter_from_label(
            "receive_packets_total", "Receive Packets", broadband["receive_packets"]
        )
        yield counter_from_label(
            "transmit_bytes_total", "Transmit Bytes", broadband["transmit_bytes"]
        )
        yield counter_from_label(
            "transmit_packets_total", "Transmit Packets", broadband["transmit_packets"]
        )

        fiber_up = GaugeMetricFamily("fiber_wan_up", "Optical WAN is up")
        fiber_up.add_metric([], 1 if fiber["wan_up"] else 0)
        yield fiber_up

        value_gauge = GaugeMetricFamily(
            "fiber_optical_value",
            "Raw current value reported by the router's fiber diagnostics page "
            "(vendor-reported, units not confirmed)",
            labels=["metric"],
        )
        threshold_gauge = GaugeMetricFamily(
            "fiber_optical_threshold",
            "Configured alarm/warning threshold for a fiber diagnostic metric "
            "(vendor-reported, units not confirmed)",
            labels=["metric", "level", "bound"],
        )
        crossed_gauge = GaugeMetricFamily(
            "fiber_optical_threshold_crossed",
            "Whether a fiber diagnostic metric is currently past its alarm/warning threshold",
            labels=["metric", "level", "bound"],
        )
        for metric in fiber["metrics"]:
            value_gauge.add_metric([metric["name"]], metric["current"])
            for level, bounds in metric["thresholds"].items():
                for bound, (threshold, crossed) in bounds.items():
                    threshold_gauge.add_metric([metric["name"], level, bound], threshold)
                    crossed_gauge.add_metric([metric["name"], level, bound], int(crossed))
        yield value_gauge
        yield threshold_gauge
        yield crossed_gauge

        lan_port_up = GaugeMetricFamily("lan_port_up", "LAN port link state", labels=["port"])
        lan_port_speed = GaugeMetricFamily(
            "lan_port_speed_bps", "LAN port link speed in bits per second", labels=["port"]
        )
        lan_receive_bytes = CounterMetricFamily(
            "lan_port_receive_bytes_total", "LAN port received bytes", labels=["port"]
        )
        lan_receive_packets = CounterMetricFamily(
            "lan_port_receive_packets_total", "LAN port received packets", labels=["port"]
        )
        lan_transmit_bytes = CounterMetricFamily(
            "lan_port_transmit_bytes_total", "LAN port transmitted bytes", labels=["port"]
        )
        lan_transmit_packets = CounterMetricFamily(
            "lan_port_transmit_packets_total", "LAN port transmitted packets", labels=["port"]
        )
        for port in lan_ports:
            lan_port_up.add_metric([port["port"]], 1 if port["up"] else 0)
            lan_port_speed.add_metric([port["port"]], port["speed_bps"])
            lan_receive_bytes.add_metric([port["port"]], port["receive_bytes"])
            lan_receive_packets.add_metric([port["port"]], port["receive_packets"])
            lan_transmit_bytes.add_metric([port["port"]], port["transmit_bytes"])
            lan_transmit_packets.add_metric([port["port"]], port["transmit_packets"])
        yield lan_port_up
        yield lan_port_speed
        yield lan_receive_bytes
        yield lan_receive_packets
        yield lan_transmit_bytes
        yield lan_transmit_packets

        if nat is not None:
            nat_sessions_available = GaugeMetricFamily(
                "nat_sessions_available", "Total NAT sessions available"
            )
            nat_sessions_available.add_metric([], nat["sessions_available"])
            yield nat_sessions_available

            nat_sessions_in_use = GaugeMetricFamily(
                "nat_sessions_in_use", "Total NAT sessions in use"
            )
            nat_sessions_in_use.add_metric([], nat["sessions_in_use"])
            yield nat_sessions_in_use

            nat_connections = GaugeMetricFamily(
                "nat_connections",
                "Current NAT connections by IP family, protocol, and TCP state",
                labels=["ip_family", "protocol", "tcp_state"],
            )
            for (ip_family, protocol, tcp_state), count in nat["connections"].items():
                nat_connections.add_metric([ip_family, protocol, tcp_state], count)
            yield nat_connections


REGISTRY.register(CustomCollector())

if __name__ == "__main__":
    start_http_server(
        port=int(os.getenv("PORT") or 8000), addr=os.getenv("ADDR", "0.0.0.0")
    )
    while True:
        time.sleep(1)
