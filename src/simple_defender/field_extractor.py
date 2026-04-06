from __future__ import annotations

import re

from .config import (
    DEFAULT_RISKY_FIELDS,
    DEFAULT_RISKY_FIELD_PATTERNS,
    TOOL_FIELD_OVERRIDES,
    TOOL_SKIP_FIELDS,
    MAX_DEPTH,
    LARGE_ARRAY_THRESHOLD,
)
from .types import ExtractedField


class FieldExtractor:
    def _matches_wildcard(self, tool_name: str, pattern: str) -> bool:
        escaped = re.escape(pattern).replace(r"\*", ".*")
        return bool(re.match(f"^{escaped}$", tool_name))

    def _is_risky_field(self, field_name: str, tool_name: str | None = None) -> bool:
        if tool_name:
            for pattern, override_list in TOOL_FIELD_OVERRIDES.items():
                if self._matches_wildcard(tool_name, pattern):
                    return field_name in override_list

        if field_name in DEFAULT_RISKY_FIELDS:
            return True

        for pat in DEFAULT_RISKY_FIELD_PATTERNS:
            if pat.search(field_name):
                return True

        return False

    def _should_skip_field(self, field_name: str, tool_name: str | None = None) -> bool:
        if not tool_name:
            return False
        for pattern, skip_list in TOOL_SKIP_FIELDS.items():
            if self._matches_wildcard(tool_name, pattern):
                return field_name in skip_list
        return False

    def _is_paginated(self, value: dict) -> bool:
        keys = set(value.keys())
        data_keys = {"data", "results", "items", "records"}
        pagination_keys = {"next", "previous", "nextPage", "prevPage", "pagination", "page", "total", "totalCount", "hasMore", "cursor"}
        has_data = bool(keys & data_keys)
        has_pagination = bool(keys & pagination_keys)
        return has_data and has_pagination

    def _get_wrapped_data(self, value: dict) -> list | None:
        for key in ("data", "results", "items", "records"):
            if key in value and isinstance(value[key], list):
                return value[key]
        return None

    def _walk(self, value, path: str, tool_name: str | None, depth: int) -> list[ExtractedField]:
        if depth > MAX_DEPTH:
            return []

        if isinstance(value, str):
            label = path if path else "_raw"
            return [ExtractedField("_raw", label, value)]

        if value is None or not isinstance(value, (dict, list)):
            return []

        if isinstance(value, list):
            items = value[:100] if len(value) > LARGE_ARRAY_THRESHOLD else value
            results = []
            for i, item in enumerate(items):
                child_path = f"{path}[{i}]"
                results.extend(self._walk(item, child_path, tool_name, depth + 1))
            return results

        # dict
        if self._is_paginated(value):
            data_array = self._get_wrapped_data(value)
            if data_array is not None:
                data_key = next(k for k in ("data", "results", "items", "records") if k in value and isinstance(value[k], list))
                child_path = f"{path}.{data_key}" if path else data_key
                return self._walk(data_array, child_path, tool_name, depth + 1)

        wrapped = self._get_wrapped_data(value)
        if wrapped is not None:
            data_key = next(k for k in ("data", "results", "items", "records") if k in value and isinstance(value[k], list))
            child_path = f"{path}.{data_key}" if path else data_key
            return self._walk(wrapped, child_path, tool_name, depth + 1)

        results = []
        for key, val in value.items():
            if self._should_skip_field(key, tool_name):
                continue
            new_path = f"{path}.{key}" if path else key
            if isinstance(val, str) and self._is_risky_field(key, tool_name):
                results.append(ExtractedField(key, new_path, val))
            elif isinstance(val, (dict, list)):
                results.extend(self._walk(val, new_path, tool_name, depth + 1))
        return results

    def extract(self, value, tool_name: str | None = None) -> list[ExtractedField]:
        return self._walk(value, "", tool_name, 0)
