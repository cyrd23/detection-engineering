#!/usr/bin/env python3
import argparse
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

import requests
import yaml


def load_yaml(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def ensure_keys(rule: Dict[str, Any], required: List[str], path: str) -> None:
    missing = [k for k in required if k not in rule]
    if missing:
        raise ValueError(f"{path}: missing required key(s) {missing}")


def normalize_indices(index_val: Any) -> str:
    if isinstance(index_val, list):
        if not all(isinstance(x, str) for x in index_val):
            raise ValueError("index list must contain only strings")
        return ",".join(index_val)
    if isinstance(index_val, str):
        return index_val
    raise ValueError("index must be a string or list of strings")


def resolve_es_url(cli_es_url: Optional[str]) -> Optional[str]:
    if cli_es_url:
        return cli_es_url
    # Support multiple common env names
    for k in ("ELASTIC_URL", "ES_URL", "ELASTICSEARCH_URL"):
        v = os.getenv(k)
        if v:
            return v
    return None


def resolve_api_key(cli_api_key: Optional[str]) -> Optional[str]:
    if cli_api_key:
        return cli_api_key
    return os.getenv("ELASTIC_API_KEY") or os.getenv("API_KEY")


def build_es_query(rule: Dict[str, Any]) -> Dict[str, Any]:
    """
    Dry-run strategy:
    - For now we execute via Elasticsearch query_string.
    - This validates the query can be executed against the target indices.
    - (Even if your rule 'language' is kuery, many KQL-like expressions still work in query_string;
      if you later want strict KQL translation via Kibana, we can extend this.)
    """
    query = rule.get("query")
    if not isinstance(query, str) or not query.strip():
        raise ValueError("query must be a non-empty string")

    # Use query_string so you can keep using parentheses, AND/OR/NOT, field:"value", etc.
    return {
        "query": {
            "query_string": {
                "query": query,
                "default_operator": "AND",
            }
        }
    }


def es_search(
    es_url: str,
    indices: str,
    payload: Dict[str, Any],
    api_key: str,
    insecure: bool,
    size: int = 1,
    timeout: int = 30,
) -> Dict[str, Any]:
    url = f"{es_url.rstrip('/')}/{indices}/_search"
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"ApiKey {api_key}",
    }

    # Keep the dry-run light: don't pull full docs
    body = dict(payload)
    body["size"] = size
    body["_source"] = False

    r = requests.post(url, headers=headers, json=body, verify=(not insecure), timeout=timeout)
    r.raise_for_status()
    return r.json()


def main() -> None:
    p = argparse.ArgumentParser(description="Dry-run detection rule query against Elasticsearch")
    p.add_argument("--rule", required=True, help="Path to detection YAML (e.g., detections/entra/foo.yml)")
    p.add_argument("--es-url", dest="es_url", default=None, help="Elasticsearch base URL (e.g., https://1.2.3.4:9200)")
    p.add_argument("--api-key", dest="api_key", default=None, help="Elasticsearch API key (base64-ish ApiKey value)")
    p.add_argument("--insecure", action="store_true", help="Disable TLS verification (self-signed certs)")
    p.add_argument("--expect-hits", action="store_true", help="Fail if query returns 0 hits")
    args = p.parse_args()

    es_url = resolve_es_url(args.es_url)
    api_key = resolve_api_key(args.api_key)

    if not es_url or not api_key:
        print("Error: ELASTIC_URL (or --es-url) and ELASTIC_API_KEY (or --api-key) must be set (GitHub secrets).", file=sys.stderr)
        sys.exit(1)

    try:
        rule = load_yaml(args.rule)

        # Minimum metadata for a query-based rule
        ensure_keys(rule, ["name", "type", "language", "index", "query"], args.rule)

        indices = normalize_indices(rule["index"])
        payload = build_es_query(rule)

        resp = es_search(
            es_url=es_url,
            indices=indices,
            payload=payload,
            api_key=api_key,
            insecure=args.insecure,
            size=1,
        )

        total = resp.get("hits", {}).get("total", {})
        # ES can return total as int or {value, relation}
        if isinstance(total, dict):
            hits = int(total.get("value", 0))
            rel = total.get("relation", "eq")
        else:
            hits = int(total)
            rel = "eq"

        print(f"OK: Dry-run executed for: {rule.get('name')}")
        print(f"  Rule file: {args.rule}")
        print(f"  Indices: {indices}")
        print(f"  Hits: {hits} (relation: {rel})")

        if hits == 0:
            msg = "WARN: Query executed successfully but returned 0 hits in this environment/time window."
            if args.expect_hits:
                print("ERROR: " + msg, file=sys.stderr)
                sys.exit(2)
            else:
                print(msg)

        sys.exit(0)

    except requests.exceptions.SSLError as e:
        print(f"ERROR: TLS/SSL error talking to Elasticsearch. If using self-signed certs, pass --insecure. Details: {e}", file=sys.stderr)
        sys.exit(3)
    except requests.exceptions.HTTPError as e:
        # Print ES error body if present (super helpful)
        try:
            body = e.response.json()
        except Exception:
            body = e.response.text if e.response is not None else str(e)
        print(f"ERROR: Elasticsearch HTTP error: {e}\nResponse: {body}", file=sys.stderr)
        sys.exit(4)
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Network/HTTP error: {e}", file=sys.stderr)
        sys.exit(4)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(5)


if __name__ == "__main__":
    main()
