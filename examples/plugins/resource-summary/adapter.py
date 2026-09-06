#!/usr/bin/env python3
"""Reference adapter: consumes sofka's request and emits its report protocol."""
import json
import sys

request = json.load(sys.stdin)
if request.get("schema_version") != 1:
    sys.exit("unsupported request schema_version")

obj = request.get("object") or {}
metadata = obj.get("metadata", {})
sections = [{
    "title": "Selection",
    "columns": ["Field", "Value"],
    "rows": [
        ["Context", request.get("context") or "inferred"],
        ["Kind", obj.get("kind", "")],
        ["Namespace", metadata.get("namespace", "")],
        ["Name", metadata.get("name", "")],
    ],
}]
if request.get("inputs", {}).get("detail") == "true":
    sections.append({
        "title": "Labels",
        "columns": ["Label", "Value"],
        "rows": [[key, value] for key, value in sorted(metadata.get("labels", {}).items())],
    })
json.dump({"schema_version": 1, "title": "Resource summary", "sections": sections}, sys.stdout)
