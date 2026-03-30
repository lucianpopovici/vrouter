"""Tests for modules/base.py — FileBasedAdapter and ModeAwareAdapter."""

import json
import pytest
from modules.base import FileBasedAdapter, ModeAwareAdapter


SCHEMA = {
    "module": "test",
    "version": "1.2.3",
    "keys": {
        "INT_KEY": {
            "type": "int",
            "description": "An integer key",
            "default": 10,
            "min": 1,
            "max": 100,
            "group": "General",
            "mandatory": False,
        },
        "STR_KEY": {
            "type": "str",
            "description": "A string key",
            "default": "hello",
            "group": "General",
            "mandatory": False,
        },
        "BOOL_KEY": {
            "type": "bool",
            "description": "A boolean key",
            "default": False,
            "group": "Advanced",
            "mandatory": False,
        },
    },
}


@pytest.fixture
def adapter(tmp_path):
    schema_path = tmp_path / "schema.json"
    schema_path.write_text(json.dumps(SCHEMA))
    runtime_path = tmp_path / "runtime.json"
    return FileBasedAdapter(
        base_dir=str(tmp_path),
        schema_file="schema.json",
        runtime_file="runtime.json",
    )


class TestFileBasedAdapterGet:
    def test_get_default(self, adapter):
        assert adapter.get("INT_KEY") == 10
        assert adapter.get("STR_KEY") == "hello"
        assert adapter.get("BOOL_KEY") is False

    def test_get_case_insensitive(self, adapter):
        assert adapter.get("int_key") == 10

    def test_get_unknown_raises(self, adapter):
        with pytest.raises(KeyError):
            adapter.get("NONEXISTENT")


class TestFileBasedAdapterSet:
    def test_set_int(self, adapter):
        coerced = adapter.set("INT_KEY", "42")
        assert coerced == 42
        assert adapter.get("INT_KEY") == 42

    def test_set_int_below_min(self, adapter):
        with pytest.raises(ValueError, match="minimum"):
            adapter.set("INT_KEY", 0)

    def test_set_int_above_max(self, adapter):
        with pytest.raises(ValueError, match="maximum"):
            adapter.set("INT_KEY", 101)

    def test_set_bool_true(self, adapter):
        adapter.set("BOOL_KEY", "true")
        assert adapter.get("BOOL_KEY") is True

    def test_set_bool_false(self, adapter):
        adapter.set("BOOL_KEY", "false")
        assert adapter.get("BOOL_KEY") is False

    def test_set_bool_numeric(self, adapter):
        adapter.set("BOOL_KEY", "1")
        assert adapter.get("BOOL_KEY") is True

    def test_set_unknown_raises(self, adapter):
        with pytest.raises(KeyError):
            adapter.set("BOGUS", "value")

    def test_set_persists_to_file(self, adapter, tmp_path):
        adapter.set("INT_KEY", 55)
        runtime = json.loads((tmp_path / "runtime.json").read_text())
        assert runtime["INT_KEY"] == 55


class TestFileBasedAdapterReset:
    def test_reset_removes_override(self, adapter):
        adapter.set("INT_KEY", 55)
        adapter.reset("INT_KEY")
        assert adapter.get("INT_KEY") == 10  # back to default

    def test_reset_unknown_raises(self, adapter):
        with pytest.raises(KeyError):
            adapter.reset("BOGUS")


class TestFileBasedAdapterSchemaRows:
    def test_schema_rows_returns_all_keys(self, adapter):
        rows = adapter.schema_rows()
        keys = {r["key"] for r in rows}
        assert keys == {"INT_KEY", "STR_KEY", "BOOL_KEY"}

    def test_schema_row_has_required_fields(self, adapter):
        rows = adapter.schema_rows()
        for row in rows:
            for field in ("key", "value", "type", "description", "default", "group"):
                assert field in row

    def test_schema_row_value_reflects_override(self, adapter):
        adapter.set("INT_KEY", 77)
        rows = adapter.schema_rows()
        row = next(r for r in rows if r["key"] == "INT_KEY")
        assert row["value"] == 77


class TestFileBasedAdapterVersion:
    def test_version(self, adapter):
        assert adapter.version == "1.2.3"

    def test_version_missing_file(self, tmp_path):
        a = FileBasedAdapter(
            base_dir=str(tmp_path),
            schema_file="missing.json",
            runtime_file="runtime.json",
        )
        assert a.version == "unknown"


class TestFileBasedAdapterKeyFilter:
    def test_key_filter_restricts_visible_keys(self, tmp_path):
        schema_path = tmp_path / "schema.json"
        schema_path.write_text(json.dumps(SCHEMA))
        adapter = FileBasedAdapter(
            base_dir=str(tmp_path),
            schema_file="schema.json",
            runtime_file="runtime.json",
            keys=["INT_KEY"],
        )
        rows = adapter.schema_rows()
        keys = {r["key"] for r in rows}
        assert keys == {"INT_KEY"}
        with pytest.raises(KeyError):
            adapter.get("STR_KEY")


# ── ModeAwareAdapter ──────────────────────────────────────────────────────────

MODE_SCHEMA = {
    "module": "stp",
    "version": "1.0",
    "keys": {
        "STP_MODE": {
            "type": "str",
            "description": "STP mode",
            "default": "stp",
            "group": "General",
            "mandatory": False,
        },
        "PRIORITY": {
            "type": "int",
            "description": "Bridge priority",
            "default": 32768,
            "min": 0,
            "max": 61440,
            "group": "STP",
            "mandatory": False,
        },
        "MST_REGION": {
            "type": "str",
            "description": "MST region name",
            "default": "default",
            "group": "MST",
            "mandatory": False,
        },
    },
}


@pytest.fixture
def mode_adapter(tmp_path):
    schema_path = tmp_path / "stp_schema.json"
    schema_path.write_text(json.dumps(MODE_SCHEMA))
    return ModeAwareAdapter(
        base_dir=str(tmp_path),
        schema_file="stp_schema.json",
        runtime_file="stp_runtime.json",
        base_keys=["STP_MODE", "PRIORITY"],
        mode_key="STP_MODE",
        conditional_keys={"mst": ["MST_REGION"]},
    )


class TestModeAwareAdapter:
    def test_base_keys_visible_by_default(self, mode_adapter):
        assert mode_adapter.get("STP_MODE") == "stp"
        assert mode_adapter.get("PRIORITY") == 32768

    def test_conditional_key_blocked_by_default(self, mode_adapter):
        with pytest.raises(KeyError, match="not available"):
            mode_adapter.get("MST_REGION")

    def test_conditional_key_visible_in_correct_mode(self, mode_adapter):
        mode_adapter.set("STP_MODE", "mst")
        assert mode_adapter.get("MST_REGION") == "default"

    def test_schema_rows_hides_invisible_keys(self, mode_adapter):
        rows = mode_adapter.schema_rows()
        keys = {r["key"] for r in rows}
        assert "MST_REGION" not in keys

    def test_schema_rows_shows_conditional_in_correct_mode(self, mode_adapter):
        mode_adapter.set("STP_MODE", "mst")
        rows = mode_adapter.schema_rows()
        keys = {r["key"] for r in rows}
        assert "MST_REGION" in keys

    def test_set_blocked_for_invisible_key(self, mode_adapter):
        with pytest.raises(KeyError):
            mode_adapter.set("MST_REGION", "region1")

    def test_reset_blocked_for_invisible_key(self, mode_adapter):
        with pytest.raises(KeyError):
            mode_adapter.reset("MST_REGION")
