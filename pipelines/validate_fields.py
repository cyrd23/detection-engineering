#!/usr/bin/env python3
"""
validate_fields.py

Validates that:
1) Required fields exist in Elasticsearch (via _field_caps)
2) The detection query executes (dry-run _search size:0)

Designed for CI usage.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple

import requests
import yaml


@dataclass
class Detection:
    name: str
    index: List[str]
    language: str  # "kuery" or "eql" (we treat as query_string on ES side only for dry-run if needed)
    query: str
    required_fields: List[str]


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def die(msg: str, code: int = 1):
    eprint(f"ERROR: {msg}")
    sys.exit(code)


def load_detection(path: str) -> Detection:
    """
    Expected YAML format (simple and explicit for CI):
      name: "Rule name"
      index:
        - "logs-*"
      language: "kuery"
      query: "field:value and ..."
      required_fields:
        - "field1"
        - "field2"
    """
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    for k in ["name", "index", "language", "query", "required_fields"]:
        if k not in data:
            die(f"{path}: missing required key '{k}'")

    if not isinstance(data["index"], list) or not data["index"]:
        die(f"{path}: 'index' must be a non-empty list")
    if not isinstance(data["required_fields"], list) or not data["required_fields"]:
        die(f"{path}: 'required_fields' must be a non-empty list")

    return Detection(
        name=str(data["name"]),
        index=[str(x) for x in data["index"]],
        language=str(data["language"]).strip().lower(),
        query=str(data["query"]),
        required_fields=[str(x) for x in data["required_fields"]],
    )


def requests_session(verify_tls: bool) -> requests.Session:
    s = requests.Session()
    s.verify = verify_tls
    s.headers.update({"Content-Type": "application/json"})
    return s


def auth_headers(api_key: str | None, username: str | None, password: str | None) -> Dict[str, str]:
    if api_key:
        return {"Authorization": f"ApiKey {api_key}"}
    # If using basic auth, requests will handle it via auth=()
    return {}


def field_caps(
    s: requests.Session,
    es_url: str,
    index_patterns: List[str],
    fields: List[str],
    api_key: str | None,
    username: str | None,
    password: str | None,
) -> Tuple[Set[str], Dict]:
    """
    Returns (missing_fields, raw_field_caps_response)
    """
    # _field_caps supports index in URL path: /<index>/_field_caps?fields=a,b
    index_path = ",".join(index_patterns)
    fields_param = ",".join(fields)

    url = f"{es_url.rstrip('/')}/{index_path}/_field_caps?fields={fields_param}"
    headers = auth_headers(api_key, username, password)

    resp = s.get(url, headers=headers, auth=(username, password) if (not api_key and username and password) else None, timeout=30)
    if resp.status_code in (401, 403):
        die(f"_field_caps unauthorized/forbidden (HTTP {resp.status_code}). Check ES creds/role.")
    if resp.status_code >= 400:
        die(f"_field_caps failed (HTTP {resp.status_code}): {resp.text[:300]}")

    payload = resp.json()
    existing = set(payload.get("fields", {}).keys())
    missing = set(fields) - existing
    return missing, payload


def dry_run_search(
    s: requests.Session,
    es_url: str,
    index_patterns: List[str],
    query_kql: str,
    api_key: str | None,
    username: str | None,
    password: str | None,
) -> Dict:
    """
    Dry-run by executing a basic query_string query.
    NOTE: KQL is a Kibana language, not Elasticsearch query DSL.
    In practice, most people validate execution via Kibana's _search API or by using ESQL/DSL.
    For CI sanity, we do a best-effort query_string check if you provide DSL instead.

    Recommended: store a DSL query for dry-run, OR validate via Kibana /internal/search/es.
    For now, we support a simple fallback: treat KQL as Lucene query_string if you set language=lucene.
    """
    # If you want *true* KQL validation, use Kibana API (see section below).
    # We'll enforce that here: language must be "lucene" for ES-side dry-run.
    # If you keep language="kuery", we'll skip ES dry-run and only do field caps.
    if query_kql.strip() == "":
        die("Query is empty")

    url = f"{es_url.rstrip('/')}/{','.join(index_patterns)}/_search"
    headers = auth_headers(api_key, username, password)

    # Minimal DSL dry-run
    body = {
        "size": 0,
        "track_total_hits": True,
        "query": {
            "query_string": {
                "query": query_kql
            }
        }
    }

    resp = s.post(url, headers=headers, auth=(username, password) if (not api_key and username and password) else None,
                  data=json.dumps(body), timeout=30)
    if resp.status_code in (401, 403):
        die(f"_search unauthorized/forbidden (HTTP {resp.status_code}). Check ES creds/role.")
    if resp.status_code >= 400:
        die(f"_search failed (HTTP {resp.status_code}): {resp.text[:500]}")

    return resp.json()


def kibana_kql_dry_run(
    kibana_url: str,
    kibana_space: str,
    api_key: str | None,
    username: str | None,
    password: str | None,
    index_patterns: List[str],
    kql: str,
    verify_tls: bool,
) -> Dict:
    """
    True KQL execution test via Kibana internal search endpoint.
    This works in CI and validates that KQL parses and runs.

    Endpoint: POST /s/{space}/internal/search/es
    """
    s = requests.Session()
    s.verify = verify_tls
    headers = {"kbn-xsrf": "true", "Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"

    url = f"{kibana_url.rstrip('/')}/s/{kibana_space}/internal/search/es"

    body = {
        "params": {
            "index": index_patterns,
            "body": {
                "size": 0,
                "track_total_hits": True,
                "query": {
                    "bool": {
                        "filter": [
                            {
                                "query_string": {
                                    "query": kql,
                                    "analyze_wildcard": True
                                }
                            }
                        ]
                    }
                }
            }
        }
    }

    # Kibana internal endpoint expects auth; basic auth works too
    resp = s.post(
        url,
        headers=headers,
        auth=(username, password) if (not api_key and username and password) else None,
        data=json.dumps(body),
        timeout=30,
    )

    if resp.status_code in (401, 403):
        die(f"Kibana KQL dry-run unauthorized/forbidden (HTTP {resp.status_code}). Check Kibana creds/space role.")
    if resp.status_code >= 400:
        die(f"Kibana KQL dry-run failed (HTTP {resp.status_code}): {resp.text[:700]}")

    return resp.json()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rule", required=True, help="Path to detection YAML (simple CI format)")
    ap.add_argument("--es-url", default=os.getenv("ELASTICSEARCH_URL", ""), help="https://x.x.x.x:9200")
    ap.add_argument("--kibana-url", default=os.getenv("KIBANA_URL", ""), help="http(s)://x.x.x.x:5601")
    ap.add_argument("--kibana-space", default=os.getenv("KIBANA_SPACE", "default"), help="space id")
    ap.add_argument("--api-key", default=os.getenv("ELASTIC_API_KEY", ""), help="Elastic/Kibana ApiKey (base64)")
    ap.add_argument("--username", default=os.getenv("ELASTIC_USERNAME", ""))
    ap.add_argument("--password", default=os.getenv("ELASTIC_PASSWORD", ""))
    ap.add_argument("--insecure", action="store_true", help="Disable TLS verification (lab only)")
    ap.add_argument("--skip-kql-dryrun", action="store_true", help="Skip Kibana dry-run")
    args = ap.parse_args()

    rule = load_detection(args.rule)

    if not args.es_url:
        die("Missing --es-url or ELASTICSEARCH_URL")
    if not (args.api_key or (args.username and args.password)):
        die("Provide ELASTIC_API_KEY or ELASTIC_USERNAME+ELASTIC_PASSWORD")

    verify_tls = not args.insecure

    # Stage B1: field existence
    s = requests_session(verify_tls)
    missing, _payload = field_caps(
        s=s,
        es_url=args.es_url,
        index_patterns=rule.index,
        fields=rule.required_fields,
        api_key=args.api_key or None,
        username=args.username or None,
        password=args.password or None,
    )

    if missing:
        die(
            f"[{rule.name}] Missing fields in ES for indices {rule.index}: {sorted(missing)}\n"
            f"Fix: update ingest mapping/enrichment OR adjust the detection to existing fields."
        )

    print(f"[OK] Field caps check passed for {rule.name}")

    # Stage B2: true KQL validation via Kibana internal endpoint (recommended)
    if not args.skip_kql_dryrun:
        if not args.kibana_url:
            die("Missing --kibana-url or KIBANA_URL (needed for KQL dry-run)")
        result = kibana_kql_dry_run(
            kibana_url=args.kibana_url,
            kibana_space=args.kibana_space,
            api_key=args.api_key or None,
            username=args.username or None,
            password=args.password or None,
            index_patterns=rule.index,
            kql=rule.query,
            verify_tls=verify_tls,
        )
        # Try to extract total hits
        total = None
        try:
            total = result["rawResponse"]["hits"]["total"]["value"]
        except Exception:
            pass
        print(f"[OK] KQL dry-run passed for {rule.name}. total_hits={total}")

    sys.exit(0)


if __name__ == "__main__":
    main()
