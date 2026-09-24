"""Stable, strict serialization and artifact provenance helpers."""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

import numpy as np
import pandas as pd


def json_safe(value):
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, np.ndarray)):
        return [json_safe(v) for v in value]
    if isinstance(value, Path):
        return str(value)
    if value is pd.NA or value is pd.NaT:
        return None
    if isinstance(value, np.generic):
        return json_safe(value.item())
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value


def canonical_json(value):
    return json.dumps(json_safe(value), ensure_ascii=False, sort_keys=True, allow_nan=False, separators=(",", ":"))


def object_hash(value):
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def file_hash(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def fingerprint_dataframe(frame):
    return object_hash({"columns": list(frame.columns), "records": frame.to_dict("records")})


def write_json(path, value):
    path = Path(path)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(json_safe(value), indent=2, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")
    temporary.replace(path)


def read_json(path):
    def invalid_constant(value):
        raise ValueError(f"Non-standard JSON constant: {value}")
    return json.loads(Path(path).read_text(encoding="utf-8"), parse_constant=invalid_constant)


def write_csv(path, frame):
    frame = frame.copy()
    for column in frame:
        if frame[column].map(lambda v: isinstance(v, (dict, list, tuple))).any():
            frame[column] = frame[column].map(lambda v: canonical_json(v) if isinstance(v, (dict, list, tuple)) else v)
    frame.to_csv(path, index=False, encoding="utf-8", lineterminator="\n")
