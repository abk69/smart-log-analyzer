#!/usr/bin/env python3
"""Professional synthetic security-log dataset generator for Smart Log Analyzer.

Produces parser-compatible Linux, Windows, and Apache log lines with optional
attack scenarios (brute force, password spray, SQLi, XSS, impossible travel,
insider threat). All randomness is driven by ``random.Random`` and an optional
``--seed`` for reproducible datasets.

This tool generates synthetic data for local testing only. It does not target
real systems and uses documentation/test IP ranges and fake usernames.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from random import Random
from typing import Iterable, Sequence


# ---------------------------------------------------------------------------
# Defaults & synthetic identity pools (documentation / private ranges only)
# ---------------------------------------------------------------------------

DEFAULT_OUTPUT = Path("logs") / "security.log"
DEFAULT_ENTRIES = 500
DEFAULT_SCENARIO = "demo"
DEFAULT_ATTACK_RATE = 0.10
DEFAULT_INTENSITY = "medium"
BASE_TIME = datetime(2026, 6, 26, 9, 0, 0)

USERS = (
    "admin",
    "john",
    "alice",
    "mike",
    "emma",
    "david",
    "developer",
    "analyst",
    "support",
    "guest",
)

PRIVILEGED_USERS = ("admin", "root", "administrator")

LINUX_IPS = tuple(f"192.168.1.{i}" for i in range(10, 60))
WINDOWS_IPS = tuple(f"10.0.0.{i}" for i in range(2, 40))
WEB_IPS = tuple(f"172.16.1.{i}" for i in range(10, 80))

# IPs mapped in analyzer.services.geolocation.DEFAULT_IP_LOCATION_MAP
GEO_MUMBAI_IP = "203.0.113.10"
GEO_NEW_YORK_IP = "198.51.100.50"
GEO_PUNE_IP = "203.0.113.20"
SPRAY_IP = "198.51.100.20"
BRUTE_IP = "203.0.113.10"

NORMAL_PATHS = (
    "/",
    "/login",
    "/products",
    "/dashboard",
    "/api/users",
    "/search?q=test",
    "/cart",
    "/checkout",
    "/about",
    "/contact",
    "/profile",
)

SENSITIVE_PATHS = (
    "/admin/users",
    "/config/settings",
    "/secret/keys",
    "/backup/dump.sql",
    "/.env",
    "/etc/passwd",
)

SQL_PAYLOADS = (
    "/login?id=1%27%20OR%201=1--",
    "/login?id=1 UNION SELECT username,password FROM users",
    "/login?id=1' OR '1'='1",
    "/q?id=1  UnIoN   aLl   SeLeCt  null",
    "/x?q=select+table_name+from+information_schema.tables",
    "/product?id=5;DROP TABLE users",
    "/x?id=1;SELECT SLEEP(5)",
    "/x?id=1;WAITFOR DELAY '0:0:5'",
    "/x?id=1;SELECT PG_SLEEP(5)",
    "/login?id=1%2527%2520OR%25201%253D1",
)

XSS_PAYLOADS = (
    "/search?q=<script>alert(1)</script>",
    "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
    "/redir?url=javascript:alert(1)",
    "/x?q=<img src=x onerror=alert(1)>",
    "/profile?name=<svg/onload=alert(1)>",
    "/x?q=<div onclick=alert(1)>",
    "/x?q=<div onmouseover=alert(1)>",
)

HTTP_METHODS = ("GET", "POST")
HTTP_STATUSES = (200, 200, 200, 201, 301, 302, 404, 500)

SCENARIO_ALIASES: dict[str, str] = {
    "demo": "demo",
    "mixed": "demo",
    "normal": "normal",
    "linux": "linux",
    "windows": "windows",
    "apache": "apache",
    "bruteforce": "bruteforce",
    "brute-force": "bruteforce",
    "brute_force": "bruteforce",
    "passwordspray": "passwordspray",
    "password-spray": "passwordspray",
    "password_spray": "passwordspray",
    "sql": "sql",
    "sqli": "sql",
    "sql-injection": "sql",
    "xss": "xss",
    "impossibletravel": "impossible_travel",
    "impossible-travel": "impossible_travel",
    "impossible_travel": "impossible_travel",
    "insider": "insider",
    "insider-threat": "insider",
    "insider_threat": "insider",
}

SCENARIO_CHOICES = sorted(set(SCENARIO_ALIASES.keys()))

INTENSITY_PRESETS: dict[str, dict[str, float | int]] = {
    "low": {"burst_failures": 5, "spray_users": 5, "attack_rate_scale": 0.5},
    "medium": {"burst_failures": 8, "spray_users": 6, "attack_rate_scale": 1.0},
    "high": {"burst_failures": 15, "spray_users": 10, "attack_rate_scale": 1.5},
}


# ---------------------------------------------------------------------------
# Core types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LogLine:
    """One generated log line with metadata for summaries."""

    timestamp: datetime
    line: str
    source: str
    kind: str


@dataclass
class GeneratorStats:
    """Counters derived from the final generated dataset."""

    total: int = 0
    linux: int = 0
    windows: int = 0
    apache: int = 0
    normal: int = 0
    suspicious: int = 0
    kinds: dict[str, int] = field(default_factory=dict)

    def observe(self, event: LogLine) -> None:
        self.total += 1
        if event.source == "linux":
            self.linux += 1
        elif event.source == "windows":
            self.windows += 1
        elif event.source == "apache":
            self.apache += 1

        self.kinds[event.kind] = self.kinds.get(event.kind, 0) + 1
        if event.kind == "normal":
            self.normal += 1
        else:
            self.suspicious += 1

    def has_kind(self, kind: str) -> bool:
        return self.kinds.get(kind, 0) > 0


@dataclass
class GeneratorContext:
    """Seeded RNG + monotonic clock for reproducible generation."""

    rng: Random
    clock: datetime
    pid: int = 1000

    def advance(self, minimum: int = 1, maximum: int = 6) -> datetime:
        self.clock += timedelta(seconds=self.rng.randint(minimum, maximum))
        return self.clock

    def set_clock(self, when: datetime) -> datetime:
        self.clock = when
        return self.clock

    def next_pid(self) -> int:
        self.pid += 1
        return self.pid

    def choice(self, seq: Sequence):
        return self.rng.choice(seq)

    def randint(self, a: int, b: int) -> int:
        return self.rng.randint(a, b)

    def random(self) -> float:
        return self.rng.random()


# ---------------------------------------------------------------------------
# Formatting helpers (must stay parser-compatible)
# ---------------------------------------------------------------------------


def format_linux_ts(ts: datetime) -> str:
    """Syslog-style stamp without year (LinuxParser injects the year)."""
    return ts.strftime("%b %d %H:%M:%S")


def format_apache_ts(ts: datetime) -> str:
    return ts.strftime("%d/%b/%Y:%H:%M:%S +0000")


def format_windows_ts(ts: datetime) -> str:
    return ts.replace(microsecond=0).isoformat()


# ---------------------------------------------------------------------------
# Primitive event generators
# ---------------------------------------------------------------------------


def generate_linux_event(
    ctx: GeneratorContext,
    *,
    success: bool | None = None,
    username: str | None = None,
    ip: str | None = None,
    when: datetime | None = None,
    kind: str = "normal",
) -> LogLine:
    ts = when if when is not None else ctx.advance()
    user = username or ctx.choice(USERS)
    address = ip or ctx.choice(LINUX_IPS)
    port = ctx.randint(30000, 60000)
    ok = ctx.random() < 0.75 if success is None else success
    verb = "Accepted" if ok else "Failed"
    line = (
        f"{format_linux_ts(ts)} server sshd[{ctx.next_pid()}]: "
        f"{verb} password for {user} from {address} port {port} ssh2"
    )
    return LogLine(timestamp=ts, line=line, source="linux", kind=kind)


def generate_windows_event(
    ctx: GeneratorContext,
    *,
    success: bool | None = None,
    username: str | None = None,
    ip: str | None = None,
    when: datetime | None = None,
    kind: str = "normal",
) -> LogLine:
    ts = when if when is not None else ctx.advance()
    user = username or ctx.choice(USERS)
    address = ip or ctx.choice(WINDOWS_IPS)
    ok = ctx.random() < 0.75 if success is None else success
    event_id = "4624" if ok else "4625"
    message = (
        "An account was successfully logged on."
        if ok
        else "An account failed to log on."
    )
    line = (
        f"{format_windows_ts(ts)} EVENT_ID={event_id} USER={user} "
        f"IP={address} MESSAGE=\"{message}\""
    )
    return LogLine(timestamp=ts, line=line, source="windows", kind=kind)


def generate_apache_event(
    ctx: GeneratorContext,
    *,
    path: str | None = None,
    method: str | None = None,
    status: int | None = None,
    ip: str | None = None,
    when: datetime | None = None,
    kind: str = "normal",
) -> LogLine:
    ts = when if when is not None else ctx.advance()
    address = ip or ctx.choice(WEB_IPS)
    http_method = method or ctx.choice(HTTP_METHODS)
    request_path = path or ctx.choice(NORMAL_PATHS)
    status_code = status if status is not None else ctx.choice(HTTP_STATUSES)
    size = ctx.randint(100, 5000)
    line = (
        f'{address} - - [{format_apache_ts(ts)}] '
        f'"{http_method} {request_path} HTTP/1.1" {status_code} {size}'
    )
    return LogLine(timestamp=ts, line=line, source="apache", kind=kind)


def generate_normal_event(ctx: GeneratorContext) -> LogLine:
    builder = ctx.choice(
        (generate_linux_event, generate_windows_event, generate_apache_event)
    )
    return builder(ctx, kind="normal")


def generate_sqli_event(
    ctx: GeneratorContext,
    *,
    when: datetime | None = None,
) -> LogLine:
    return generate_apache_event(
        ctx,
        path=ctx.choice(SQL_PAYLOADS),
        method="GET",
        status=500,
        when=when,
        kind="sql",
    )


def generate_xss_event(
    ctx: GeneratorContext,
    *,
    when: datetime | None = None,
) -> LogLine:
    return generate_apache_event(
        ctx,
        path=ctx.choice(XSS_PAYLOADS),
        method="GET",
        status=200,
        when=when,
        kind="xss",
    )


# ---------------------------------------------------------------------------
# Attack sequence generators (timestamps stay within detector windows)
# ---------------------------------------------------------------------------


def generate_bruteforce_burst(
    ctx: GeneratorContext,
    *,
    failures: int = 8,
    username: str = "admin",
    ip: str = BRUTE_IP,
    spacing_seconds: int = 4,
) -> list[LogLine]:
    """Same user + IP failed logins inside the default 120s BF window."""
    events: list[LogLine] = []
    start = ctx.advance(2, 8)
    for index in range(failures):
        when = start + timedelta(seconds=index * spacing_seconds)
        events.append(
            generate_linux_event(
                ctx,
                success=False,
                username=username,
                ip=ip,
                when=when,
                kind="bruteforce",
            )
        )
    ctx.set_clock(start + timedelta(seconds=failures * spacing_seconds + 1))
    return events


def generate_password_spray_burst(
    ctx: GeneratorContext,
    *,
    users: Sequence[str] | None = None,
    ip: str = SPRAY_IP,
    spacing_seconds: int = 5,
) -> list[LogLine]:
    """Same IP, many usernames — crosses default unique-user threshold (5)."""
    spray_users = list(users) if users is not None else list(USERS[:6])
    events: list[LogLine] = []
    start = ctx.advance(2, 8)
    for index, user in enumerate(spray_users):
        when = start + timedelta(seconds=index * spacing_seconds)
        events.append(
            generate_linux_event(
                ctx,
                success=False,
                username=user,
                ip=ip,
                when=when,
                kind="passwordspray",
            )
        )
    ctx.set_clock(start + timedelta(seconds=len(spray_users) * spacing_seconds + 1))
    return events


def generate_impossible_travel_sequence(
    ctx: GeneratorContext,
    *,
    username: str = "alice",
) -> list[LogLine]:
    """Mumbai → New York successful logins within minutes (mapped demo IPs)."""
    first = ctx.advance(3, 10)
    second = first + timedelta(minutes=5)
    events = [
        generate_linux_event(
            ctx,
            success=True,
            username=username,
            ip=GEO_MUMBAI_IP,
            when=first,
            kind="impossible_travel",
        ),
        generate_linux_event(
            ctx,
            success=True,
            username=username,
            ip=GEO_NEW_YORK_IP,
            when=second,
            kind="impossible_travel",
        ),
    ]
    ctx.set_clock(second + timedelta(seconds=30))
    return events


def generate_insider_sequence(
    ctx: GeneratorContext,
    *,
    username: str = "admin",
) -> list[LogLine]:
    """Privileged + unusual hour + sensitive access (+ unusual IP).

    Individual weak signals alone should not dominate; the combination is
    what the insider-threat heuristic scores above threshold.
    """
    # Unusual hour window for default config is [0, 5).
    base = ctx.clock.replace(hour=2, minute=10, second=0, microsecond=0)
    if base <= ctx.clock:
        base += timedelta(days=1)
    majority_ip = "10.0.0.5"
    unusual_ip = "203.0.113.99"

    events = [
        generate_linux_event(
            ctx,
            success=True,
            username=username,
            ip=majority_ip,
            when=base,
            kind="insider",
        ),
        generate_linux_event(
            ctx,
            success=True,
            username=username,
            ip=majority_ip,
            when=base + timedelta(minutes=1),
            kind="insider",
        ),
        generate_linux_event(
            ctx,
            success=True,
            username=username,
            ip=unusual_ip,
            when=base + timedelta(minutes=2),
            kind="insider",
        ),
        generate_apache_event(
            ctx,
            path=ctx.choice(SENSITIVE_PATHS),
            method="GET",
            status=200,
            ip=majority_ip,
            when=base + timedelta(minutes=3),
            kind="insider",
        ),
    ]
    ctx.set_clock(base + timedelta(minutes=4))
    return events


# ---------------------------------------------------------------------------
# Scenario composers
# ---------------------------------------------------------------------------


def _intensity_params(intensity: str) -> dict[str, float | int]:
    return dict(INTENSITY_PRESETS.get(intensity, INTENSITY_PRESETS["medium"]))


def _append_capped(
    target: list[LogLine],
    batch: Iterable[LogLine],
    limit: int,
) -> None:
    for event in batch:
        if len(target) >= limit:
            return
        target.append(event)


def _fill_normal(ctx: GeneratorContext, events: list[LogLine], entries: int) -> None:
    while len(events) < entries:
        events.append(generate_normal_event(ctx))


def _fill_attack_mix(
    ctx: GeneratorContext,
    events: list[LogLine],
    entries: int,
    *,
    attack_rate: float,
    intensity: str,
) -> None:
    params = _intensity_params(intensity)
    burst_failures = int(params["burst_failures"])
    spray_count = int(params["spray_users"])
    scale = float(params["attack_rate_scale"])
    effective_rate = min(1.0, max(0.0, attack_rate * scale))

    while len(events) < entries:
        if ctx.random() < effective_rate:
            pick = ctx.random()
            if pick < 0.25:
                _append_capped(
                    events,
                    generate_bruteforce_burst(ctx, failures=burst_failures),
                    entries,
                )
            elif pick < 0.45:
                users = list(USERS[: max(5, spray_count)])
                _append_capped(
                    events,
                    generate_password_spray_burst(ctx, users=users),
                    entries,
                )
            elif pick < 0.70:
                events.append(generate_sqli_event(ctx))
            else:
                events.append(generate_xss_event(ctx))
        else:
            events.append(generate_normal_event(ctx))


def compose_demo(
    ctx: GeneratorContext,
    entries: int,
    *,
    attack_rate: float,
    intensity: str,
) -> list[LogLine]:
    """Mixed realistic dataset with guaranteed detectable attack sequences."""
    params = _intensity_params(intensity)
    events: list[LogLine] = []

    # Guaranteed attack sequences (kept time-coherent; later sorted globally).
    guaranteed: list[LogLine] = []
    guaranteed.extend(
        generate_bruteforce_burst(ctx, failures=int(params["burst_failures"]))
    )
    guaranteed.extend(
        generate_password_spray_burst(
            ctx, users=list(USERS[: max(5, int(params["spray_users"]))])
        )
    )
    for _ in range(3):
        guaranteed.append(generate_sqli_event(ctx))
        guaranteed.append(generate_xss_event(ctx))
    guaranteed.extend(generate_impossible_travel_sequence(ctx))
    guaranteed.extend(generate_insider_sequence(ctx))

    if entries <= len(guaranteed):
        # Prefer keeping complete sequences; truncate only if forced by size.
        return sorted(guaranteed, key=lambda e: e.timestamp)[:entries]

    events.extend(guaranteed)
    _fill_attack_mix(
        ctx,
        events,
        entries,
        attack_rate=attack_rate,
        intensity=intensity,
    )
    return _finalize(events, entries)


def compose_normal(ctx: GeneratorContext, entries: int) -> list[LogLine]:
    events: list[LogLine] = []
    _fill_normal(ctx, events, entries)
    return _finalize(events, entries)


def compose_source(
    ctx: GeneratorContext,
    entries: int,
    source: str,
) -> list[LogLine]:
    events: list[LogLine] = []
    while len(events) < entries:
        if source == "linux":
            events.append(
                generate_linux_event(ctx, success=ctx.random() < 0.8, kind="normal")
            )
        elif source == "windows":
            events.append(
                generate_windows_event(ctx, success=ctx.random() < 0.8, kind="normal")
            )
        else:
            events.append(generate_apache_event(ctx, kind="normal"))
    return _finalize(events, entries)


def compose_bruteforce(
    ctx: GeneratorContext,
    entries: int,
    *,
    intensity: str,
) -> list[LogLine]:
    failures = int(_intensity_params(intensity)["burst_failures"])
    events: list[LogLine] = []
    while len(events) < entries:
        _append_capped(
            events,
            generate_bruteforce_burst(ctx, failures=failures),
            entries,
        )
        if len(events) < entries and ctx.random() < 0.2:
            events.append(generate_normal_event(ctx))
    return _finalize(events, entries)


def compose_passwordspray(
    ctx: GeneratorContext,
    entries: int,
    *,
    intensity: str,
) -> list[LogLine]:
    spray_users = list(USERS[: max(5, int(_intensity_params(intensity)["spray_users"]))])
    events: list[LogLine] = []
    while len(events) < entries:
        _append_capped(
            events,
            generate_password_spray_burst(ctx, users=spray_users),
            entries,
        )
        if len(events) < entries and ctx.random() < 0.2:
            events.append(generate_normal_event(ctx))
    return _finalize(events, entries)


def compose_sql(ctx: GeneratorContext, entries: int) -> list[LogLine]:
    events: list[LogLine] = []
    while len(events) < entries:
        if ctx.random() < 0.85:
            events.append(generate_sqli_event(ctx))
        else:
            events.append(generate_apache_event(ctx, kind="normal"))
    return _finalize(events, entries)


def compose_xss(ctx: GeneratorContext, entries: int) -> list[LogLine]:
    events: list[LogLine] = []
    while len(events) < entries:
        if ctx.random() < 0.85:
            events.append(generate_xss_event(ctx))
        else:
            events.append(generate_apache_event(ctx, kind="normal"))
    return _finalize(events, entries)


def compose_impossible_travel(ctx: GeneratorContext, entries: int) -> list[LogLine]:
    events: list[LogLine] = []
    while len(events) < entries:
        _append_capped(events, generate_impossible_travel_sequence(ctx), entries)
        if len(events) < entries:
            events.append(generate_normal_event(ctx))
    return _finalize(events, entries)


def compose_insider(ctx: GeneratorContext, entries: int) -> list[LogLine]:
    events: list[LogLine] = []
    while len(events) < entries:
        _append_capped(events, generate_insider_sequence(ctx), entries)
        if len(events) < entries:
            events.append(generate_normal_event(ctx))
    return _finalize(events, entries)


def _finalize(events: list[LogLine], entries: int) -> list[LogLine]:
    """Trim to exact size and sort chronologically (attack windows preserved)."""
    trimmed = events[:entries]
    return sorted(trimmed, key=lambda e: (e.timestamp, e.line))


# ---------------------------------------------------------------------------
# Public generation API
# ---------------------------------------------------------------------------


def normalize_scenario(name: str) -> str:
    key = (name or "").strip().lower()
    if key not in SCENARIO_ALIASES:
        raise ValueError(
            f"Unknown scenario '{name}'. "
            f"Choose from: {', '.join(sorted(set(SCENARIO_ALIASES.values())))}"
        )
    return SCENARIO_ALIASES[key]


def validate_attack_rate(value: float) -> float:
    if not 0.0 <= value <= 1.0:
        raise ValueError("attack-rate must be between 0.0 and 1.0 inclusive")
    return value


def generate_events(
    entries: int,
    *,
    scenario: str = DEFAULT_SCENARIO,
    seed: int | None = None,
    attack_rate: float = DEFAULT_ATTACK_RATE,
    intensity: str = DEFAULT_INTENSITY,
    start_time: datetime | None = None,
) -> list[LogLine]:
    """Generate ``entries`` parser-compatible log events in memory."""
    if entries < 0:
        raise ValueError("entries must be >= 0")
    if entries == 0:
        return []

    scenario_key = normalize_scenario(scenario)
    rate = validate_attack_rate(attack_rate)
    intensity_key = (intensity or DEFAULT_INTENSITY).strip().lower()
    if intensity_key not in INTENSITY_PRESETS:
        raise ValueError(
            f"Unknown intensity '{intensity}'. Choose from: low, medium, high"
        )

    ctx = GeneratorContext(
        rng=Random(seed),
        clock=start_time or BASE_TIME,
        pid=1000,
    )

    if scenario_key == "demo":
        return compose_demo(
            ctx, entries, attack_rate=rate, intensity=intensity_key
        )
    if scenario_key == "normal":
        return compose_normal(ctx, entries)
    if scenario_key in {"linux", "windows", "apache"}:
        return compose_source(ctx, entries, scenario_key)
    if scenario_key == "bruteforce":
        return compose_bruteforce(ctx, entries, intensity=intensity_key)
    if scenario_key == "passwordspray":
        return compose_passwordspray(ctx, entries, intensity=intensity_key)
    if scenario_key == "sql":
        return compose_sql(ctx, entries)
    if scenario_key == "xss":
        return compose_xss(ctx, entries)
    if scenario_key == "impossible_travel":
        return compose_impossible_travel(ctx, entries)
    if scenario_key == "insider":
        return compose_insider(ctx, entries)

    raise ValueError(f"Unhandled scenario '{scenario_key}'")


def write_events(events: Sequence[LogLine], output: Path) -> Path:
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(f"{event.line}\n" for event in events)
    output.write_text(text, encoding="utf-8")
    return output


def collect_stats(events: Sequence[LogLine]) -> GeneratorStats:
    stats = GeneratorStats()
    for event in events:
        stats.observe(event)
    return stats


def print_summary(
    *,
    output: Path,
    entries: int,
    seed: int | None,
    scenario: str,
    attack_rate: float,
    intensity: str,
    stats: GeneratorStats,
) -> None:
    seed_label = "None (non-deterministic)" if seed is None else str(seed)
    print("=" * 60)
    print("SMART LOG ANALYZER - DATASET GENERATOR")
    print("=" * 60)
    print()
    print(f"Output       : {output.as_posix()}")
    print(f"Entries      : {entries}")
    print(f"Seed         : {seed_label}")
    print(f"Scenario     : {scenario}")
    print(f"Attack Rate  : {attack_rate:.2f}")
    print(f"Intensity    : {intensity}")
    print()
    print("Generated:")
    print()
    print(f"Linux        : {stats.linux}")
    print(f"Windows      : {stats.windows}")
    print(f"Apache       : {stats.apache}")
    print()
    print(f"Normal       : {stats.normal}")
    print(f"Suspicious   : {stats.suspicious}")
    print()
    print(f"Brute Force       : {'YES' if stats.has_kind('bruteforce') else 'NO'}")
    print(f"Password Spray    : {'YES' if stats.has_kind('passwordspray') else 'NO'}")
    print(f"SQL Injection     : {'YES' if stats.has_kind('sql') else 'NO'}")
    print(f"XSS               : {'YES' if stats.has_kind('xss') else 'NO'}")
    print(
        f"Impossible Travel : "
        f"{'YES' if stats.has_kind('impossible_travel') else 'NO'}"
    )
    print(f"Insider Threat    : {'YES' if stats.has_kind('insider') else 'NO'}")
    print("=" * 60)


def generate_dataset(
    entries: int = DEFAULT_ENTRIES,
    *,
    scenario: str = DEFAULT_SCENARIO,
    seed: int | None = None,
    output: str | Path = DEFAULT_OUTPUT,
    attack_rate: float = DEFAULT_ATTACK_RATE,
    intensity: str = DEFAULT_INTENSITY,
    quiet: bool = False,
) -> tuple[Path, list[LogLine], GeneratorStats]:
    """Generate events, write them to ``output``, and return path/events/stats."""
    scenario_key = normalize_scenario(scenario)
    events = generate_events(
        entries,
        scenario=scenario_key,
        seed=seed,
        attack_rate=attack_rate,
        intensity=intensity,
    )
    if len(events) != entries:
        raise RuntimeError(
            f"Generator invariant failed: expected {entries} events, got {len(events)}"
        )
    if entries > 0 and not all(isinstance(e.line, str) and e.line for e in events):
        raise RuntimeError("Generator invariant failed: empty or non-string lines")

    path = write_events(events, Path(output))
    if entries > 0 and (not path.exists() or path.stat().st_size == 0):
        raise RuntimeError("Generator invariant failed: output file missing or empty")

    stats = collect_stats(events)
    if not quiet:
        print_summary(
            output=path,
            entries=entries,
            seed=seed,
            scenario=scenario_key,
            attack_rate=attack_rate,
            intensity=intensity,
            stats=stats,
        )
    return path, events, stats


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _parse_attack_rate(raw: str) -> float:
    try:
        value = float(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("attack-rate must be a number") from exc
    if not 0.0 <= value <= 1.0:
        raise argparse.ArgumentTypeError(
            "attack-rate must be between 0.0 and 1.0 inclusive"
        )
    return value


def _parse_entries(raw: str) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("entries must be an integer") from exc
    if value < 0:
        raise argparse.ArgumentTypeError("entries must be >= 0")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="generate_logs.py",
        description=(
            "Generate reproducible, parser-compatible synthetic security logs "
            "for Smart Log Analyzer."
        ),
    )
    parser.add_argument(
        "--entries",
        type=_parse_entries,
        default=DEFAULT_ENTRIES,
        help=f"Number of log lines to generate (default: {DEFAULT_ENTRIES})",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="RNG seed for reproducible output",
    )
    parser.add_argument(
        "--scenario",
        default=DEFAULT_SCENARIO,
        metavar="NAME",
        help=(
            "Dataset scenario "
            f"(default: {DEFAULT_SCENARIO}). "
            "Aliases: mixed→demo, sqli→sql, brute-force→bruteforce, ..."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Output path (default: {DEFAULT_OUTPUT.as_posix()})",
    )
    parser.add_argument(
        "--attack-rate",
        type=_parse_attack_rate,
        default=DEFAULT_ATTACK_RATE,
        help=(
            "Fraction of mixed/demo filler activity that is attack-related "
            f"(0.0–1.0, default: {DEFAULT_ATTACK_RATE}). "
            "Scenario-specific generators take precedence over this rate."
        ),
    )
    parser.add_argument(
        "--intensity",
        choices=sorted(INTENSITY_PRESETS.keys()),
        default=DEFAULT_INTENSITY,
        help=(
            "Attack intensity for demo/bruteforce/passwordspray "
            f"(default: {DEFAULT_INTENSITY})"
        ),
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress the summary banner",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 2
        return 2 if code else 0

    try:
        scenario = normalize_scenario(args.scenario)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    try:
        generate_dataset(
            entries=args.entries,
            scenario=scenario,
            seed=args.seed,
            output=args.output,
            attack_rate=args.attack_rate,
            intensity=args.intensity,
            quiet=args.quiet,
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"Error: unable to write output: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
