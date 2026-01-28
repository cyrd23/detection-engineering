#!/usr/bin/env python3
import argparse
import sys
from typing import Any, Dict, Optional

import requests
import yaml

def die(msg: str, code: int = 1) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)

def load_rule(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        die(f"{path}: rule file is not a YAML mapping/object")
    return data

def build_es_query_from_kql(kql: str) -> Dict[str, Any]:
    # Minimal “dry-run” without KQL->DSL translation:
    # We use query_string which ES supports; not perfect parity with KQL,
    # but good enough to validate syntax/connectivity and index access.
    return {
        "query": {
            "query_string": {
                "query": kql
            }
        },
        "size": 0
    }

def main() -> None:
    ap = argparse.ArgumentParser(description="Dry-run detection query against Elasticsearch (_search size:0)")
    ap.add_argument("--rule", required=True, help="Path to detection YAML")
    ap.add_argument("--es-url", required=True, help="Elasticsearch base URL")
    ap.add_argument("--api-key", required=True, help="Elastic API key")
    ap.add_argument("--insecure", action="store_true", help="Disable TLS verification (self-signed certs)")
    args = ap.parse_args()

    rule = load_rule(args.rule)
    for k in ["index", "query", "language"]:
        if k not in rule:
            die(f"{args.rule}: missing required key '{k}'")

    index_patterns = rule["index"]
    if not isinstance(index_patterns, list) or not index_patterns:
        die(f"{args.rule}: 'index' must be a non-empty list")

    query = rule["query"]
    if not isinstance(query, str) or not query.strip():
        die(f"{args.rule}: 'query' must be a non-empty string")

    index_expr = ",".join(index_patterns)
    url = f"{args.es_url.rstrip('/')}/{index_expr}/_search"

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"ApiKey {args.api_key}",
    }

    payload = build_es_query_from_kql(query)

    try:
        r = requests.post(url, headers=headers, json=payload, timeout=30, verify=(not args.insecure))
    except requests.exceptions.SSLError as e:
        die(f"TLS/SSL error talking to Elasticsearch. If self-signed, pass --insecure. Details: {e}")
    except requests.RequestException as e:
        die(f"HTTP error talking to Elasticsearch: {e}")

    if r.status_code >= 400:
        die(f"{args.rule}: dry-run failed ({r.status_code}): {r.text[:500]}")

    print(f"OK: {args.rule}: dry-run query executed successfully.")
    sys.exit(0)

if __name__ == "__main__":
    main()
