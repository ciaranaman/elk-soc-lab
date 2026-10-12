# ELK SOC Lab

A reproducible local security investigation lab using Elasticsearch, Logstash and Kibana.
Send synthetic login and process events through a JSON HTTP pipeline, search normalized fields,
and practise triaging suspicious activity. This is a portfolio implementation, not a production SIEM.

## Architecture

```text
Python sample sender -> localhost:8080 -> Logstash -> Elasticsearch
                                                   ^
                                                   |
                         localhost:5601 -> Kibana --+
```

All host ports bind to **127.0.0.1**. Elasticsearch stores data in a Docker volume.
All three images use the same pinned version (9.5.5), configurable in `.env`.
There are no real credentials, malware or external threat feeds.

## Requirements

- Docker Engine / Docker Desktop with Docker Compose v2 and Linux containers.
- Allocate at least 6 GB RAM to Docker, and allow roughly 10 GB free disk for images/data.
- Python 3.9+ for the demo and verification (no extra packages).
- Internet access for the initial image download.

On Windows, use Docker Desktop's WSL2 backend. On Linux, Elasticsearch requires
`vm.max_map_count` of at least 262144; follow the linked Elastic Docker documentation
for your host or Docker VM. This project does not modify host settings automatically.

## Quick start

Clone or download this repository and open a terminal in its folder:

```sh
git clone https://github.com/ciaranaman/elk-soc-lab.git
cd elk-soc-lab
```

Copy the example settings:

```sh
# Linux / macOS
cp .env.example .env
```

```powershell
# Windows PowerShell
Copy-Item .env.example .env
```

Start the stack, then send and verify the samples:

```sh
docker compose config --quiet
docker compose up -d
python scripts/demo.py
```

Use `python3` on systems where that is the Python 3 command. The script waits for
readiness, creates field mappings, submits seven events through Logstash and checks
the indexed IDs, expected tags and Kibana status. Initial downloads/startup can take
several minutes. A timeout is a failed verification, not evidence of success.

Open [Kibana](http://127.0.0.1:5601).
Go to **Stack Management -> Data Views -> Create data view**:
use `soc-lab` as the index pattern and `@timestamp` as the time field.
Open Discover and select that view. Set the time range to Last 15 minutes.
Sample timestamps use the current UTC time; rerun the script to bring them into a new time range.

## What the samples demonstrate

- Five failed logins for lab-admin from the documentation address 192.0.2.25.
- A successful login from the same address, for correlation practice.
- An encoded PowerShell command recorded as text. No command in a sample is executed.

The filter adds candidate tags to individual events. It does **not** implement a
brute-force threshold, scheduled alert or automatic response. Invalid JSON or events
missing event.id/category/outcome go to `soc-quarantine`; this is basic validation,
not a complete schema enforcement system. Inputs are trusted synthetic data.

Try these Kibana Query Language (KQL) filters in Discover:

```text
event.category: authentication and event.outcome: failure
source.ip: "192.0.2.25" and user.name: "lab-admin"
tags: encoded_powershell_candidate
```

Here KQL means **Kibana Query Language**, which differs from Microsoft's Kusto Query
Language used with Sentinel. Investigate the failed logins followed by success in
timestamp order; corroborate with identity and endpoint evidence in a real case.

Suggested ATT&CK hypotheses: T1110 (Brute Force) for repeated login failures and
T1059.001 (PowerShell) for the process event. These are investigation hypotheses,
not proof of malicious activity. Legitimate administration can generate similar events.

## Verification and diagnostics

```sh
docker compose ps
docker compose logs --tail=100 elasticsearch logstash kibana
python scripts/demo.py
```

The sender uses stable event IDs: repeated runs update the same seven documents.
It verifies those IDs rather than trusting the index's total count.

- Connection refused: check Docker is running, services are up and ports are free.
- Elasticsearch exits: inspect logs for memory or vm.max_map_count errors.
- Kibana is still starting: wait, then rerun verification.
- No Discover results: select soc-lab and widen the time range.
- Port conflict: change ES_PORT, KIBANA_PORT or LOGSTASH_PORT in .env and recreate
  with `docker compose up -d`; the Python script reads those settings too.
- Pipeline changes: run `docker compose restart logstash`.
- Quarantined events: create another data view for soc-quarantine and inspect tags.
- Existing index with incompatible mappings: use a fresh lab volume or inspect mappings;
  the script does not silently overwrite an existing index's schema.

Optional pipeline syntax check, after Elasticsearch is running:

```sh
docker compose run --rm --no-deps logstash --config.test_and_exit
```

A syntax check does not prove ingestion works; the Python verification checks the full path.

## Local-development boundary

Authentication and TLS are disabled to keep this synthetic, single-machine demo
easy to inspect. Loopback bindings reduce exposure; local processes and other
containers able to reach the Docker network can still access these services.
Do not change the bindings to 0.0.0.0, expose this stack to the internet, deploy it
on a shared host, or ingest sensitive logs without adding authentication, TLS,
least-privilege service accounts and appropriate network controls.
Use only synthetic data here. Storage is unbounded in this small lab; production
requires retention/lifecycle policies, backup, access control and capacity planning.

## Stop or reset

Stop while keeping indexed data:

```sh
docker compose down
```

Delete this project's containers and data volume (permanent lab-data reset):

```sh
docker compose down -v
```

## Portfolio evidence

After running verification, capture your own Discover screenshot and a short incident
write-up describing the timeline, candidate techniques, false positives, evidence
needed and response recommendations. Claim only the work you actually ran and reviewed.

Suggested CV wording after completing the lab:
"Built a Docker Compose ELK lab with JSON ingestion, normalized security fields,
synthetic authentication/process events, and automated end-to-end verification."

## Validation status

Project prepared from documented Elastic configuration. It has not been executed
in the author's delivery session because the local execution environment was unavailable.
Run the documented syntax and end-to-end checks before claiming runtime validation.

## References

- [Elasticsearch Docker installation](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-docker-prod)
- [Logstash Docker configuration](https://www.elastic.co/docs/reference/logstash/docker-config)
- [Logstash settings](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [MITRE ATT&CK T1110](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)

The project's code and synthetic samples are MIT licensed. Elastic products have
their own licensing terms; the project license does not relicense the container images.
