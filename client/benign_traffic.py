import requests, random, time, subprocess, sys

VICTIM = "victim"

def http_burst():
    for _ in range(random.randint(1, 5)):
        try:
            r = requests.get(f"http://{VICTIM}/", timeout=3)
            print(f"[http] {r.status_code}", flush=True)
        except requests.RequestException as e:
            print(f"[http] failed: {e}", flush=True)
        time.sleep(random.uniform(0.1, 1.0))

def ping_check():
    try:
        subprocess.run(["ping", "-c", "3", VICTIM], stdout=subprocess.DEVNULL, timeout=5)
        print("[ping] ok", flush=True)
    except Exception as e:
        print(f"[ping] failed: {e}", flush=True)

while True:
    action = random.choice([http_burst, ping_check])
    action()
    time.sleep(random.uniform(0.1, 1))
