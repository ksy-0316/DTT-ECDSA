"""Random VANET traffic-report message generation.

Section VI-A: "The reported message m is a JSON-encoded traffic record
containing the message type, the timestamp, the location and the event details,
whose serialised length is about 300 bytes."

Each generated message carries the five required fields:

    Message Type | Message ID | Timestamp | Location | Event Details
"""

from __future__ import annotations

import json
import random
import secrets
import time
from datetime import datetime, timedelta, timezone

MESSAGE_TYPES = [
    ("EMERGENCY_HAZARD_WARNING", "HW"),
    ("TRAFFIC_CONGESTION_REPORT", "TC"),
    ("ROAD_WORKS_NOTIFICATION", "RW"),
    ("ADVERSE_WEATHER_ALERT", "AW"),
    ("COLLISION_RISK_WARNING", "CR"),
    ("EMERGENCY_VEHICLE_APPROACHING", "EV"),
    ("SLOW_VEHICLE_INDICATION", "SV"),
    ("STATIONARY_VEHICLE_ALERT", "SA"),
]

ROADS = [
    "G4-Jingang-Expwy", "S21-Binhai-Ring", "Zhongshan-Rd-N",
    "Chaoyang-Ave-E", "Xueyuan-Rd-S", "Hongqi-Blvd-W", "Jianguo-Viaduct",
]

EVENT_CAUSES = [
    "breakdown in left lane, hazard lights on",
    "rear-end collision blocking two lanes",
    "heavy rain, standing water on surface",
    "debris on carriageway after cargo spill",
    "queue tail ahead, abrupt deceleration",
    "dense fog, visibility below 80 m",
    "ambulance requesting lane clearance",
]

SUB_CAUSES = ["minor", "moderate", "severe", "critical"]
WEATHER = ["clear", "rain", "fog", "snow", "wind"]


def _timestamp(rng: random.Random) -> str:
    base = datetime(2026, 3, 20, 17, 45, 22, 367000, tzinfo=timezone.utc)
    shift = timedelta(seconds=rng.randint(-86400, 86400),
                      milliseconds=rng.randint(0, 999))
    return (base + shift).strftime("%Y-%m-%dT%H:%M:%S.") + \
           f"{(base + shift).microsecond // 1000:03d}Z"


def generate_message(rng: random.Random | None = None) -> dict:
    """Produce one random JSON-serialisable traffic record (~300 bytes)."""
    rng = rng or random.Random()
    mtype, code = rng.choice(MESSAGE_TYPES)
    ts = _timestamp(rng)
    return {
        "Message Type": mtype,
        "Message ID": f"VANETs-{code}-{ts[:10].replace('-', '')}-"
                      f"{rng.randint(1, 999):03d}",
        "Timestamp": ts,
        "Location": {
            "latitude": round(rng.uniform(39.7000, 40.2000), 4),
            "longitude": round(rng.uniform(116.1000, 116.7000), 4),
            "road": rng.choice(ROADS),
            "lane": rng.randint(1, 4),
        },
        "Event Details": {
            "cause": rng.choice(EVENT_CAUSES),
            "severity": rng.choice(SUB_CAUSES),
            "speed_kmh": rng.randint(0, 120),
            "lanes": rng.randint(1, 3),
            "weather": rng.choice(WEATHER),
            "duration_s": rng.randint(60, 3600),
        },
    }


def serialize(message: dict) -> bytes:
    """Canonical byte encoding of m, used for hashing and for |m|."""
    return json.dumps(message, separators=(",", ":"),
                      sort_keys=True, ensure_ascii=False).encode("utf-8")


def new_sid(counter: int) -> bytes:
    """Unique session identifier (16 bytes).

    Section V-D: "sid embeds a monotone counter and a timestamp"; it is bound
    into c = H(sid || m) so that replayed transcripts fail the freshness test.
    """
    return (counter.to_bytes(4, "big")
            + int(time.time_ns() // 1000).to_bytes(8, "big")[-8:]
            + secrets.token_bytes(4))


def format_message(message: dict, indent: int = 4) -> str:
    pad = " " * indent
    body = json.dumps(message, indent=2, ensure_ascii=False)
    return "\n".join(pad + line for line in body.splitlines())
