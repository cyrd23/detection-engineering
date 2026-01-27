#!/usr/bin/env python3

import argparse
import os
import sys
import yaml
import requests
import urllib3

# -----------------------------
# Helpers
# -----------------------------

def load_rule(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)


def get_required_fields(rule):
    rf = rule.get("required_fields", [])
    fields = []

    for entry in rf:
        if isinstance(entry, dict) and "name" in entry:
            fields.append(entry["name"])
        elif isinstance(entry, str):
            fields.append(entry)

    return fields


def get_index_patterns(rule):
    idx = rule.get("index", [])

    if isinstance(idx, str):
        return [idx]

    return idx


# -----------------------------
# Elasticsearch field caps
# -----------------------------

def field_caps(es_url, index, required_fields, headers, auth=None, insecure=False):
    session = requests.Session()

    if insecure:
        session.verify = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    fields_param = ",".join(required_fields)

    url = f"{es_url.rstrip('/')}/{index}/_field_caps"
    params = {"fields": fields_param}

    resp = session.get(
        url,
        params=params,
        headers=headers,
        auth=auth,
        timeout=30,
    )

    resp.raise_for_status()
    payload = resp.json()

    found = payload.get("fields", {})
    missing = [f for f in required_fields if f not in found]

    return missing, payload


# -----------------------------
# Main
# -----------------------------

def main():
    parser = argparse.ArgumentParser(description="Validate detection fields exist in Elasticsearch")

    parser.add_argument("--rule", required=True)
    parser.add_argument("--es-url", required=True)
    parser.add_argument("--kibana-url")
    parser.add_argument("--kibana-space")
    parser.add_argument("--username")
    parser.add_argument("--password")
    parser.add_argument("--api-key")
    parser.add_argument("--insecure", action="store_true")

    args = parser.parse_args()

    rule = load_rule(args.rule)

    required_fields = get_required_fields(rule)
    index_patterns = get_index_patterns(rule)

    if not required_fields:
        print("❌ No required_fields defined in rule")
        sys.exit(1)

    if not index_patterns:
        print("❌ No index patterns defined in rule")
        sys.exit(1)

    headers = {}

    auth = None

    if args.api_key:
        headers["Authorization"] = f"ApiKey {args.api_key}"
    elif args.username and args.password:
        auth = (args.username, args.password)
    else:
        print("❌ Must supply API key or username/password")
        sys.exit(1)

    overall_missing = False

    for index in index_patterns:
        print(f"\n🔍 Checking index pattern: {index}")

        missing, _payload = field_caps(
            es_url=args.es_url,
            index=index,
            required_fields=required_fields,
            headers=headers,
            auth=auth,
            insecure=args.insecure,
        )

        if missing:
            overall_missing = True
            print("❌ Missing fields:")
            for f in missing:
                print(f"   - {f}")
        else:
            print("✅ All required fields exist")

    if overall_missing:
        print("\n🚫 Validation failed — missing required fields")
        sys.exit(1)

    print("\n🎉 Field validation passed")


if __name__ == "__main__":
    main()
