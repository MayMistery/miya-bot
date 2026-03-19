"""Tests for challenge validation and type safety in the fanout topology."""

from __future__ import annotations

import json

from miya.topology.fanout_topo import _validate_challenges


class TestValidateChallenges:
    """Unit tests for _validate_challenges() type-checking helper."""

    def test_none_returns_none(self):
        assert _validate_challenges(None) is None

    def test_valid_list_of_dicts(self):
        raw = [
            {"name": "Easy-Gin", "target": "http://10.0.0.1:16235", "category": "web"},
            {"name": "Easy-JWT", "target": "http://10.0.0.1:17855", "category": "web"},
        ]
        result = _validate_challenges(raw)
        assert result is not None
        assert len(result) == 2
        assert result[0]["name"] == "Easy-Gin"
        assert result[1]["name"] == "Easy-JWT"

    def test_string_triggers_json_parse(self):
        """A JSON string (from accidental str() conversion) should be parsed back."""
        raw = json.dumps([
            {"name": "chall1", "target": "http://host:1234"},
            {"name": "chall2", "target": "http://host:5678"},
        ])
        result = _validate_challenges(raw)
        assert result is not None
        assert len(result) == 2
        assert result[0]["name"] == "chall1"

    def test_non_json_string_returns_none(self):
        """A random string (not JSON) should return None gracefully."""
        result = _validate_challenges("not a json string at all")
        assert result is None

    def test_python_repr_string_returns_none(self):
        """str() of a Python list (single quotes) is not valid JSON → None."""
        raw = str([{"name": "Easy-Gin", "target": "http://host:1234"}])
        # Python repr uses single quotes, which is invalid JSON
        result = _validate_challenges(raw)
        assert result is None

    def test_list_of_strings_skips_invalid_items(self):
        """If predefined is a list of strings (not dicts), all items are skipped."""
        result = _validate_challenges(["Easy-Gin", "Easy-JWT"])
        assert result is None

    def test_mixed_list_keeps_valid_dicts(self):
        """Mixed list: keeps valid dicts, skips non-dict items."""
        raw = [
            {"name": "valid-challenge", "target": "http://host:1234"},
            "not-a-dict",
            42,
            {"name": "another-valid", "target": "http://host:5678"},
        ]
        result = _validate_challenges(raw)
        assert result is not None
        assert len(result) == 2
        assert result[0]["name"] == "valid-challenge"
        assert result[1]["name"] == "another-valid"

    def test_dict_without_name_skipped(self):
        """Dicts missing the 'name' key are skipped."""
        raw = [
            {"target": "http://host:1234"},  # no name
            {"name": "has-name", "target": "http://host:5678"},
        ]
        result = _validate_challenges(raw)
        assert result is not None
        assert len(result) == 1
        assert result[0]["name"] == "has-name"

    def test_empty_list_returns_none(self):
        result = _validate_challenges([])
        assert result is None

    def test_integer_input_returns_none(self):
        result = _validate_challenges(42)
        assert result is None

    def test_json_string_non_list_returns_none(self):
        """JSON string that parses to a dict (not a list) → None."""
        result = _validate_challenges('{"name": "single"}')
        assert result is None

    def test_preserves_all_fields(self):
        """Valid dicts should preserve all original fields."""
        raw = [{"name": "chall", "target": "http://h:1", "category": "web", "points": 100}]
        result = _validate_challenges(raw)
        assert result is not None
        assert result[0] == raw[0]
