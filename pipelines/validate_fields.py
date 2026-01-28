#!/usr/bin/env python3
import argparse
import sys
import json
from typing import Any, Dict, List, Tuple, Optional

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

def normalize_required_fields(rule: Dict[str, Any], path: str) -> List[Dict[str, str]]:
    rf = rule.get("required_fields")
    if rf is None:
        die(f"{path}: missing required key 'required_fields'")
    if not isinstance(rf, list) or not rf:
        die(f"{path}: 'required_fields' must be a non-empty list")

    out: List[Dict[str, str]] = []
    for i, item in enumerate(rf):
        if not isinstance(item, dict):
            die(f"{path}: required_fields[{i}] must be an object like {{name,type}}")
        name = item.get("name")
        ftype = item.get("type")
        if not name or not isinstance(name, str):
            die(f"{path}: required_fields[{i}] missing/invalid 'name'")
        if not ftype or not isinstance(ftype, str):
            die(f"{path}: required_fields[{i}] missing/invalid 'type'")
        out.append({"name": name, "type": ftype})
    return out

def validate_rule_shape(rule: Dict[str, Any], path: str) -> None:
    # These are the keys your CI has been enforcing via earlier errors
    required_top = ["name", "type", "language", "index", "query", "required_fields"]
    for k in required_top:
        if k not in rule:
            die(f"{path}: missing required key '{k}'")

    if not isinstance(rule.get("index"), list) or not rule["index"]:
        die(f"{path}: 'index' must be a non-empty list (e.g. ['logs-azure.signinlogs*'])")

    if not isinstance(rule.get("query"), str) or not rule["query"].strip():
        die(f"{path}: 'query' must be a non-empty string")

def es_field_caps(
    es_url: str,
    index_patterns: List[str],
    fields: List[str],
    api_key: Optional[str],
    username: Optional[str],
    password: Optional[str],
    insecure: bool,
) -> Dict[str, Any]:
    # Use a single request across all index patterns (comma-separated)
    index_expr = ",".join(index_patterns)
    url = f"{es_url.rstrip('/')}/{index_expr}/_field_caps"
    params = [("fields", f) for f in fields]

    headers: Dict[str, str] = {"Accept": "application/json"}
    auth = None
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    elif username and password:
        auth = (username, password)

    s = requests.Session()
    verify = not insecure

    try:
        resp = s.get(url, headers=headers, auth=auth, params=params, timeout=30, verify=verify)
    except requests.exceptions.SSLError as e:
        die(f"TLS/SSL error talking to Elasticsearch. If this is a self-signed cert, pass --insecure. Details: {e}")
    except requests.RequestException as e:
        die(f"HTTP error talking to Elasticsearch: {e}")

    if resp.status_code >= 400:
        die(f"Elasticsearch field_caps failed ({resp.status_code}): {resp.text[:500]}")

    try:
        return resp.json()
    except Exception:
        die(f"Elasticsearch returned non-JSON response: {resp.text[:200]}")

def find_missing_fields(field_caps_payload: Dict[str, Any], required: List[Dict[str, str]]) -> List[str]:
    # Payload shape: {"fields": {"fieldA": {"keyword": {...}}, "fieldB": {...}}}
    fields_obj = field_caps_payload.get("fields") or {}
    missing: List[str] = []

    for req in required:
        name = req["name"]
        expected_type = req["type"]
        entry = fields_obj.get(name)

        if not entry:
            missing.append(f"{name} (expected: {expected_type})")
            continue

        # entry is a dict keyed by ES type ("keyword", "text", "ip", etc.)
        # Accept missing type mismatch as "missing/mismatch"
        if expected_type not in entry.keys():
            missing.append(f"{name} (expected type: {expected_type}; got: {','.join(entry.keys())})")

    return missing

def main() -> None:
    p = argparse.ArgumentParser(description="Validate required_fields exist in Elasticsearch via _field_caps")
    p.add_argument("--rule", required=True, help="Path to a detection YAML rule")
    p.add_argument("--es-url", required=True, help="Elasticsearch base URL, e.g. https://192.168.40.20:9200")
    p.add_argument("--api-key", default="", help="Elastic API key (base64 token)")
    p.add_argument("--username", default="", help="Basic auth username (optional if api-key provided)")
    p.add_argument("--password", default="", help="Basic auth password (optional if api-key provided)")
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification (self-signed certs)")

    args = p.parse_args()

    rule = load_rule(args.rule)
    validate_rule_shape(rule, args.rule)
    required_fields = normalize_required_fields(rule, args.rule)

    index_patterns = rule["index"]
    fields = [rf["name"] for rf in required_fields]

    payload = es_field_caps(
        es_url=args.es_url,
        index_patterns=index_patterns,
        fields=fields,
        api_key=args.api_key or None,
        username=args.username or None,
        password=args.password or None,
        insecure=args.insecure,
    )

    missing = find_missing_fields(payload, required_fields)
    if missing:
        print(f"ERROR: {args.rule}: missing required field(s):")
        for m in missing:
            print(f"  - {m}")
        sys.exit(1)

    print(f"OK: {args.rule}: all required_fields exist in Elasticsearch.")
    sys.exit(0)

if __name__ == "__main__":
    main()
