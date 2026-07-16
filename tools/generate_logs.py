import argparse
import random
from pathlib import Path
from datetime import datetime, timedelta

# ==========================================================
# Configuration
# ==========================================================

OUTPUT_DIR = Path("logs")
OUTPUT_FILE = OUTPUT_DIR / "security.log"

USERS = [
    "admin",
    "john",
    "alice",
    "mike",
    "emma",
    "david",
    "root",
    "guest",
    "abhishek"
]

LINUX_IPS = [
    f"192.168.1.{i}"
    for i in range(10, 60)
]

WINDOWS_IPS = [
    f"10.0.0.{i}"
    for i in range(2, 40)
]

WEB_IPS = [
    f"172.16.1.{i}"
    for i in range(10, 80)
]

WEB_PATHS = [
    "/",
    "/login",
    "/products",
    "/cart",
    "/checkout",
    "/about",
    "/contact",
    "/profile",
]

# ==========================================================
# Utility Functions
# ==========================================================

current_time = datetime(
    2026,
    6,
    26,
    9,
    0,
    0,
)

pid = 1000


def next_time():

    global current_time

    current_time += timedelta(
        seconds=random.randint(1, 6)
    )

    return current_time


def next_pid():

    global pid

    pid += 1

    return pid


# ==========================================================
# Linux Logs
# ==========================================================

def linux_success():

    ts = next_time()

    return (
        f"{ts:%b %d %H:%M:%S} "
        f"server "
        f"sshd[{next_pid()}]: "
        f"Accepted password for "
        f"{random.choice(USERS)} "
        f"from "
        f"{random.choice(LINUX_IPS)} "
        f"port "
        f"{random.randint(30000,60000)} "
        f"ssh2"
    )


def linux_failed():

    ts = next_time()

    return (
        f"{ts:%b %d %H:%M:%S} "
        f"server "
        f"sshd[{next_pid()}]: "
        f"Failed password for "
        f"{random.choice(USERS)} "
        f"from "
        f"{random.choice(LINUX_IPS)} "
        f"port "
        f"{random.randint(30000,60000)} "
        f"ssh2"
    )


# ==========================================================
# Windows Logs
# ==========================================================

def windows_success():

    ts = next_time()

    return (
        f"{ts.isoformat()} "
        f"EVENT_ID=4624 "
        f"USER={random.choice(USERS)} "
        f"IP={random.choice(WINDOWS_IPS)} "
        f'MESSAGE="An account was successfully logged on."'
    )


def windows_failed():

    ts = next_time()

    return (
        f"{ts.isoformat()} "
        f"EVENT_ID=4625 "
        f"USER={random.choice(USERS)} "
        f"IP={random.choice(WINDOWS_IPS)} "
        f'MESSAGE="An account failed to log on."'
    )


# ==========================================================
# Apache Logs
# ==========================================================

def apache_request():

    ts = next_time()

    return (
        f'{random.choice(WEB_IPS)} '
        f'- - '
        f'[{ts:%d/%b/%Y:%H:%M:%S +0000}] '
        f'"GET '
        f'{random.choice(WEB_PATHS)} '
        f'HTTP/1.1" '
        f'200 '
        f'{random.randint(200,5000)}'
    )

# ==========================================================
# Brute Force Attack
# ==========================================================

def brute_force():

    logs = []

    username = "admin"
    ip = "203.0.113.10"

    for _ in range(5):

        ts = next_time()

        logs.append(
            f"{ts:%b %d %H:%M:%S} "
            f"server "
            f"sshd[{next_pid()}]: "
            f"Failed password for "
            f"{username} "
            f"from "
            f"{ip} "
            f"port "
            f"{random.randint(30000,60000)} "
            f"ssh2"
        )

    return logs


# ==========================================================
# Password Spray
# ==========================================================

def password_spray():

    logs = []

    ip = "198.51.100.20"

    users = [
        "admin",
        "john",
        "alice",
        "mike",
        "emma",
    ]

    for user in users:

        ts = next_time()

        logs.append(
            f"{ts:%b %d %H:%M:%S} "
            f"server "
            f"sshd[{next_pid()}]: "
            f"Failed password for "
            f"{user} "
            f"from "
            f"{ip} "
            f"port "
            f"{random.randint(30000,60000)} "
            f"ssh2"
        )

    return logs


# ==========================================================
# SQL Injection
# ==========================================================

SQL_PAYLOADS = [

    "/login?id=1%27%20OR%201=1--",

    "/login?id=1 UNION SELECT username,password FROM users",

    "/product?id=5;DROP TABLE users",

]


def sql_injection():

    ts = next_time()

    return (
        f'{random.choice(WEB_IPS)} '
        f'- - '
        f'[{ts:%d/%b/%Y:%H:%M:%S +0000}] '
        f'"GET '
        f'{random.choice(SQL_PAYLOADS)} '
        f'HTTP/1.1" '
        f'500 '
        f'{random.randint(300,800)}'
    )


# ==========================================================
# XSS Attack
# ==========================================================

XSS_PAYLOADS = [

    "/search?q=<script>alert(1)</script>",

    "/comment?msg=<img src=x onerror=alert(1)>",

    "/profile?name=<svg/onload=alert(1)>",

]


def xss():

    ts = next_time()

    return (
        f'{random.choice(WEB_IPS)} '
        f'- - '
        f'[{ts:%d/%b/%Y:%H:%M:%S +0000}] '
        f'"GET '
        f'{random.choice(XSS_PAYLOADS)} '
        f'HTTP/1.1" '
        f'200 '
        f'{random.randint(200,800)}'
    )


# ==========================================================
# Random Normal Event
# ==========================================================

def normal_event():

    event = random.choice(

        [

            linux_success,

            linux_failed,

            windows_success,

            windows_failed,

            apache_request,

        ]

    )

    return event()

# ==========================================================
# Dataset Generator
# ==========================================================

def generate_dataset(entries, scenario):

    OUTPUT_DIR.mkdir(exist_ok=True)

    logs = []

    if scenario == "bruteforce":

        while len(logs) < entries:
            logs.extend(brute_force())

    elif scenario == "passwordspray":

        while len(logs) < entries:
            logs.extend(password_spray())

    elif scenario == "sql":

        while len(logs) < entries:
            logs.append(sql_injection())

    elif scenario == "xss":

        while len(logs) < entries:
            logs.append(xss())

    elif scenario == "linux":

        while len(logs) < entries:

            if random.random() < 0.8:
                logs.append(linux_success())
            else:
                logs.append(linux_failed())

    elif scenario == "windows":

        while len(logs) < entries:

            if random.random() < 0.8:
                logs.append(windows_success())
            else:
                logs.append(windows_failed())

    elif scenario == "apache":

        while len(logs) < entries:
            logs.append(apache_request())

    else:

        while len(logs) < entries:

            choice = random.randint(1, 100)

            if choice <= 50:
                logs.append(normal_event())

            elif choice <= 60:
                logs.extend(brute_force())

            elif choice <= 70:
                logs.extend(password_spray())

            elif choice <= 80:
                logs.append(sql_injection())

            elif choice <= 90:
                logs.append(xss())

            else:
                logs.append(normal_event())

    logs = logs[:entries]

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:

        for log in logs:
            file.write(log + "\n")

    print("=" * 60)
    print("SECURITY DATASET GENERATED")
    print("=" * 60)
    print(f"Scenario      : {scenario}")
    print(f"Total Logs    : {len(logs)}")
    print(f"Output File   : {OUTPUT_FILE}")
    print("=" * 60)


# ==========================================================
# Main
# ==========================================================

def main():

    parser = argparse.ArgumentParser(
        description="Security Dataset Generator"
    )

    parser.add_argument(
        "--entries",
        type=int,
        default=500,
        help="Number of log entries"
    )

    parser.add_argument(
        "--scenario",
        default="demo",
        choices=[
            "demo",
            "linux",
            "windows",
            "apache",
            "bruteforce",
            "passwordspray",
            "sql",
            "xss",
        ],
        help="Dataset Scenario"
    )

    args = parser.parse_args()

    generate_dataset(
        entries=args.entries,
        scenario=args.scenario
    )


if __name__ == "__main__":
    main()