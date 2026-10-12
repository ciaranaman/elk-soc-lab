"""Send synthetic events through Logstash and verify Elasticsearch and Kibana.
Python 3.9+; standard library only. Run from any directory.
"""
import json
import os
from pathlib import Path
import sys
import time
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[1]
# Read simple KEY=value settings without executing the .env file.
settings = {}
if (ROOT / ".env").exists():
    for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            settings[key.strip()] = value.strip().strip('"').strip("'")

def base(key, default):
    port = int(os.environ.get(key, settings.get(key, default)))
    if not 1 <= port <= 65535:
        raise ValueError("Invalid port: " + key)
    return "http://127.0.0.1:" + str(port)

ES = base("ES_PORT", "9200")
LS = base("LOGSTASH_PORT", "8080")
KB = base("KIBANA_PORT", "5601")

def request(url, data=None, method=None):
    body = None if data is None else json.dumps(data).encode("utf-8")
    req = Request(url, data=body, method=method,
                  headers={"Content-Type": "application/json"})
    with urlopen(req, timeout=10) as response:
        payload = response.read()
        return json.loads(payload) if payload else {}

def wait(label, action, timeout=300):
    deadline = time.monotonic() + timeout
    last_error = "not ready"
    while time.monotonic() < deadline:
        try:
            value = action()
            if value:
                print(label + ": OK")
                return value
        except (URLError, TimeoutError, OSError, ValueError) as exc:
            last_error = str(exc)
        time.sleep(3)
    raise RuntimeError(label + " timed out: " + last_error)

def healthy():
    health = request(ES + "/_cluster/health")
    return health["status"] in ("yellow", "green")

def kibana_ready():
    status = request(KB + "/api/status")
    return status.get("status", {}).get("overall", {}).get("level") == "available"

def main():
    wait("Elasticsearch", healthy)
    # Explicit mapping gives fields appropriate types for security investigations.
    mapping = {"mappings": {"properties": {
        "@timestamp": {"type": "date"},
        "event": {"properties": {key: {"type": "keyword"}
                  for key in ("id", "category", "action", "outcome")}},
        "source": {"properties": {"ip": {"type": "ip"}}},
        "user": {"properties": {"name": {"type": "keyword"}}},
        "host": {"properties": {"name": {"type": "keyword"}}},
        "process": {"properties": {"name": {"type": "keyword"},
                    "command_line": {"type": "wildcard"}}},
        "tags": {"type": "keyword"}
    }}}
    try:
        request(ES + "/soc-lab", mapping, "PUT")
    except HTTPError as exc:
        payload = json.loads(exc.read())
        if payload.get("error", {}).get("type") != "resource_already_exists_exception":
            raise RuntimeError("Index creation failed: " + json.dumps(payload)) from exc

    events = json.loads((ROOT / "samples/security-events.json").read_text(encoding="utf-8"))
    for event in events:
        event["@timestamp"] = datetime.now(timezone.utc).isoformat()
        def send(event=event):
            request(LS, event)
            return True
        wait("Send " + event["event"]["id"], send)
    ids = [event["event"]["id"] for event in events]
    def ingested():
        request(ES + "/soc-lab/_refresh", {}, "POST")
        result = request(ES + "/soc-lab/_search", {
            "size": len(ids), "query": {"terms": {"event.id": ids}}})
        hits = result["hits"]["hits"]
        if {hit["_source"]["event"]["id"] for hit in hits} != set(ids):
            return False
        tagged = {hit["_source"]["event"]["id"]: hit["_source"].get("tags", [])
                  for hit in hits}
        if any("authentication_failure" not in tagged[event_id]
               for event_id in ids if event_id.startswith("auth-failure")):
            raise ValueError("Authentication failure tags missing")
        if "encoded_powershell_candidate" not in tagged["process-1"]:
            raise ValueError("PowerShell candidate tag missing")
        return True
    wait("All seven events indexed with expected tags", ingested)
    wait("Kibana", kibana_ready)
    print("Verification passed. Open " + KB + " and create data view soc-lab.")
    print("Repeated runs overwrite these seven demo IDs rather than duplicating them.")

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("Verification failed: " + str(exc), file=sys.stderr)
        sys.exit(1)
