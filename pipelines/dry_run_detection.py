#!/usr/bin/env python3
import os
import sys
import glob
import json
import yaml
import requests
from typing import Dict, Any, List, Tuple

def die(msg: str, code: int = 1):
    print(f"[ERROR] {msg}", file=sys.stderr)
    sys.exit(code)

def warn(msg: str):
    print(f"[WARN] {msg}", file=sys.stderr)

def info(msg: str):
    print(f"[INFO] {msg}")

def es_request(method: str, url: str, api_key: str, path: str, params: Dict[str, str] = None, body: Dict[str, Any] = None):
    full = url.rstrip("/") + path
    headers = {
        "Authorization": f"ApiKey {api_key}",
        "Content-Type": "application/json",
    }
    r = requests.request(method, full, headers=headers, params=params, data=json.dumps(body) if body is not None else None, verify=False, timeout=30)
    return r

def flatten_fields(obj: Any, prefix: str = "") -> List[str]:
    """
    Extract dot-notated fields referenced in a detection selection/filter dict.
    Example:
      {"a.b": ["x"], "c": {"d": 1}} -> ["a.b", "c.d"]
    """
    fields = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, dict):
                fields.extend(flatten_fields(v, f"{prefix}{k}."))
            else:
                fields.append(f"{prefix}{k}")
    return fields

def normalize_value(v):
    if isinstance(v, list):
        return v
    return [v]

def build_clause(field: str, value) -> Dict[str, Any]:
    """
    Build an ES clause from field/value. Lists become terms, scalar becomes term.
    """
    vals = normalize_value(value)
    if len(vals) == 1:
        return {"term": {field: vals[0]}}
    return {"terms": {field: vals}}

def build_named_query(detection: Dict[str, Any], name: str) -> Dict[str, Any]:
    """
    detection[name] may be a dict of field->value(s)
    """
    block = detection.get(name)
    if not isinstance(block, dict):
        die(f"detection.{name} must be a dict (got {type(block).__name__})")
    must = []
    for field, val in block.items():
        must.append(build_clause(field, val))
    return {"bool": {"must": must}} if must else {"match_all": {}}

def tokenize(expr: str) -> List[str]:
    # very small tokenizer for: names, and/or/not, parentheses
    expr = expr.replace("(", " ( ").replace(")", " ) ")
    return [t for t in expr.split() if t]

def parse_condition(expr: str, named_queries: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """
    Supports expressions like:
      selection and not filter_geo
      selection and (filter1 or filter2)
    """
    tokens = tokenize(expr.lower())
    i = 0

    def parse_primary():
        nonlocal i
        if i >= len(tokens):
            die("Unexpected end of condition")
        tok = tokens[i]
        if tok == "(":
            i += 1
            node = parse_or()
            if i >= len(tokens) or tokens[i] != ")":
                die("Missing ')' in condition")
            i += 1
            return node
        if tok == "not":
            i += 1
            node = parse_primary()
            return {"bool": {"must_not": [node]}}
        # name
        i += 1
        if tok not in named_queries:
            die(f"Condition references unknown block '{tok}'. Available: {', '.join(named_queries.keys())}")
        return named_queries[tok]

    def parse_and():
        nonlocal i
        left = parse_primary()
        while i < len(tokens) and tokens[i] == "and":
            i += 1
            right = parse_primary()
            left = {"bool": {"must": [left, right]}}
        return left

    def parse_or():
        nonlocal i
        left = parse_and()
        while i < len(tokens) and tokens[i] == "or":
            i += 1
            right = parse_and()
            left = {"bool": {"should": [left, right], "minimum_should_match": 1}}
        return left

    node = parse_or()
    if i != len(tokens):
        die(f"Unexpected token(s) at end of condition: {' '.join(tokens[i:])}")
    return node

def main():
    elastic_url = os.getenv("ELASTIC_URL")
    api_key = os.getenv("ELASTIC_API_KEY")
    index_pattern = os.getenv("INDEX_PATTERN", "logs-*")

    if not elastic_url or not api_key:
        die("ELASTIC_URL and ELASTIC_API_KEY must be set (GitHub secrets).")

    det_files = sorted(glob.glob("detections/**/*.yml", recursive=True) + glob.glob("detections/**/*.yaml", recursive=True))
    if not det_files:
        die("No detection YAML files found under detections/")

    info(f"Found {len(det_files)} detection file(s). Using INDEX_PATTERN={index_pattern}")

    failures = 0

    for path in det_files:
        info(f"--- Dry-run: {path}")
        with open(path, "r", encoding="utf-8") as f:
            doc = yaml.safe_load(f)

        # We expect a sigma-ish structure:
        # title, logsource{product,service}, detection{selection, filter_*, condition}, level
        title = doc.get("title", path)
        detection = doc.get("detection")
        if not isinstance(detection, dict):
            warn(f"{title}: missing/invalid detection block; skipping")
            failures += 1
            continue

        condition = detection.get("condition")
        if not isinstance(condition, str):
            die(f"{title}: detection.condition must be a string")

        # Build named queries for any dict blocks in detection except "condition"
        named_queries = {}
        referenced_fields = []
        for k, v in detection.items():
            if k == "condition":
                continue
            if isinstance(v, dict):
                named_queries[k.lower()] = build_named_query(detection, k)
                referenced_fields.extend(flatten_fields(v))

        # Field existence check (fast fail)
        if referenced_fields:
            r = es_request(
                "GET",
                elastic_url,
                api_key,
                "/_field_caps",
                params={"fields": ",".join(sorted(set(referenced_fields))), "index": index_pattern},
                body=None,
            )
            if r.status_code != 200:
                warn(f"{title}: field_caps failed ({r.status_code}): {r.text[:300]}")
                failures += 1
                continue

            caps = r.json().get("fields", {})
            missing = [fld for fld in set(referenced_fields) if fld not in caps]
            if missing:
                warn(f"{title}: missing field(s) in index pattern '{index_pattern}': {', '.join(sorted(missing))}")
                failures += 1
                continue

        # Build final ES query from condition
        try:
            es_query = parse_condition(condition, named_queries)
        except SystemExit:
            raise
        except Exception as e:
            warn(f"{title}: failed to parse condition '{condition}': {e}")
            failures += 1
            continue

        # Execute dry-run search (size 0)
        body = {"size": 0, "track_total_hits": True, "query": es_query}
        r = es_request("POST", elastic_url, api_key, f"/{index_pattern}/_search", body=body)

        if r.status_code != 200:
            warn(f"{title}: _search failed ({r.status_code}): {r.text[:500]}")
            failures += 1
            continue

        total = r.json().get("hits", {}).get("total", {}).get("value", 0)
        info(f"{title}: query OK (hits={total})")

    if failures:
        die(f"{failures} detection(s) failed dry-run validation.", 2)

    info("All detections passed dry-run validation ✅")

if __name__ == "__main__":
    main()
