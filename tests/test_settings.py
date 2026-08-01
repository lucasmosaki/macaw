"""Tests for the local profile data layout."""

from __future__ import annotations

import json

from config.settings import DataPaths, Settings


def test_settings_are_saved_at_the_profile_root(tmp_path) -> None:
    paths = DataPaths(tmp_path)
    settings = Settings(username="alice", listen_port=45813, retention_days=14)

    settings.save(paths)

    assert paths.settings_file == tmp_path / "settings.json"
    assert json.loads(paths.settings_file.read_text(encoding="utf-8")) == {
        "username": "alice",
        "listen_host": "0.0.0.0",
        "listen_port": 45813,
        "retention_days": 14,
    }
    assert not paths.legacy_settings_file.exists()


def test_settings_load_from_the_legacy_config_location(tmp_path) -> None:
    paths = DataPaths(tmp_path)
    paths.legacy_settings_file.parent.mkdir(parents=True)
    paths.legacy_settings_file.write_text(
        '{"username": "alice", "listen_port": 45813, "retention_days": 14}',
        encoding="utf-8",
    )

    settings = Settings.load(paths)

    assert settings.username == "alice"
    assert settings.listen_port == 45813
    assert settings.retention_days == 14
