#!/usr/bin/env python3
"""
validate_fields.py

Purpose:
  - Parse Sigma YAML detections under detections/**.yml(yaml)
  - Extract field names used in the `detection:` section
  - Validate those fields exist in Elasticsearch via _field_caps
Auth:
  - Uses Elasticsearch API Key auth from env:
      ELASTICSEARCH_URL
      ELASTIC_API_KEY
Notes:
  - verify=False is used to tolerate self-signed certs in lab; tighten for prod.
"""

import os
import sys
import glob
import re
from typing import Any, Dict, Set, List

import yaml
import requests


FIELD_RE = re.compile(r"^[a-zA-Z0-9_.@-]+$")


def collect_fields(node: Any, out: Set[str]) -> None:
    """
    Recursively walk a Sigma detection tree and extract likely field names.

    Sigma convention: field names are commonly used as dict keys.
    Example:
      detection:
        selection:
          source.ip: 1.2.3.4
          user.name|contains: admin
    We normalize keys by stripping Sigma pipe modifiers (e.g., "|contains").
    """
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(k, str):
                base_key = k.split("|", 1)[0].strip()
                # heuristic: field keys typically contain dots
                if "." in base_key and FIELD_RE.match(base_key):
                    out.add(base_key)
            collect_fields(v, out)
    elif isinstance(node, list):
        for item in node:
            collect_fields(item, out)


def load_sigma_fields(path: str) -> Set[str]:
    with open(path, "r", encoding="utf-8") as f:
        doc = yaml.safe_load(f) or {}
    detection = doc.get("detection", {}) or {}
    fields: Set[str] = set()
    collect_fields(detection, fields)
    return fields


def es_field_caps(es_url: str, api_key: str, fields: Set[str]) -> Dict[str, Any]:
    """
    Call Elasticsearch _field_caps for a set of fields.
    """
    headers = {"Authorization": f"ApiKey {api_key}"}
    params = {"fields": ",".join(sorted(fields))}

    # For lab environments with self-signed certs
    r = requests.get(
        f"{es_url.rstrip('/')}/_field_caps",
        params=params,
        headers=headers,
        verify=False,
        timeout=30,
    )
    r.raise_for_status()
    return r.json()


def find_detection_files() -> List[str]:
    paths = sorted(
        glob.glob("detections/**/*.yml", recursive=True)
        + glob.glob("detections/**/*.yaml", recursive=True)
    )
    return paths


def main() -> int:
    es_url = os.environ.get("ELASTICSEARCH_URL")
    api_key = os.environ.get("ELASTIC_API_KEY")

    if not es_url:
        print("Missing env var: ELASTICSEARCH_URL", file=sys.stderr)
        return 2
    if not api_key:
        print("Missing env var: ELASTIC_API_KEY", file=sys.stderr)
        return 2

    paths = find_detection_files()
    if not paths:
        print("No detections found under detections/**", file=sys.stderr)
        return 3

    missing_any = False

    for path in paths:
        fields = load_sigma_fields(path)

        if not fields:
            print(f"[WARN] {path}: no fields detected under `detection:`")
            continue

        try:
            caps = es_field_caps(es_url, api_key, fields)
        except requests.HTTPError as e:
            body = ""
            try:
                body = e.response.text  # type: ignore[attr-defined]
            except Exception:
                pass
            print(f"[ERROR] {path}: _field_caps HTTP error: {e}\n{body}", file=sys.stderr)
            return 4
        except Exception as e:
            print(f"[ERROR] {path}: _field_caps request failed: {e}", file=sys.stderr)
            return 4

        existing = set((caps.get("fields") or {}).keys())
        missing = sorted(list(fields - existing))

        if missing:
            missing_any = True
            print(f"\n[FAIL] {path} missing fields ({len(missing)}):")
            for f in missing:
                print(f"  - {f}")
        else:
            print(f"[OK] {path} all fields exist ({len(fields)} checked)")

    return 1 if missing_any else 0


if __name__ == "__main__":
    raise SystemExit(main())
