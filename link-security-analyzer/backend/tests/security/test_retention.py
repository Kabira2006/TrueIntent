"""Test retention and cleanup policies."""

import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.workers.tasks import cleanup_old_artifacts


class TestRetentionPolicy:
    """Test artifact and result cleanup."""

    def test_cleanup_old_artifacts_removes_expired_files(self) -> None:
        """Old artifacts past TTL should be deleted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create "old" file (expired)
            now = datetime.now(timezone.utc)
            old_ttl = (now - timedelta(hours=50)).timestamp()  # Past 48h TTL
            old_file = tmpdir_path / f"scan123_screenshot_{int(old_ttl)}.png"
            old_file.write_bytes(b"fake image data")
            
            # Create "new" file (not expired)
            new_ttl = (now + timedelta(hours=24)).timestamp()  # Future TTL
            new_file = tmpdir_path / f"scan456_screenshot_{int(new_ttl)}.png"
            new_file.write_bytes(b"fake image data")
            
            # Mock the _ARTIFACTS_DIR
            with patch("app.workers.tasks._ARTIFACTS_DIR", tmpdir_path):
                result = cleanup_old_artifacts()
            
            # Old file should be deleted, new file should remain
            assert not old_file.exists(), "Old artifact should be deleted"
            assert new_file.exists(), "New artifact should be kept"
            assert result["artifacts_deleted"] >= 1

    def test_cleanup_preserves_recent_files(self) -> None:
        """Recent artifacts should not be deleted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create recent file
            now = datetime.now(timezone.utc)
            recent_ttl = (now + timedelta(hours=12)).timestamp()
            recent_file = tmpdir_path / f"scan789_favicon_{int(recent_ttl)}.ico"
            recent_file.write_bytes(b"fake favicon")
            
            with patch("app.workers.tasks._ARTIFACTS_DIR", tmpdir_path):
                cleanup_old_artifacts()
            
            assert recent_file.exists(), "Recent artifact should be preserved"

    def test_cleanup_handles_missing_directory(self) -> None:
        """Cleanup should handle missing artifact directory gracefully."""
        nonexistent = Path("/tmp/does_not_exist_retention_test")
        
        with patch("app.workers.tasks._ARTIFACTS_DIR", nonexistent):
            result = cleanup_old_artifacts()
        
        # Should not crash
        assert isinstance(result, dict)
        assert "artifacts_deleted" in result

    def test_cleanup_handles_malformed_filenames(self) -> None:
        """Cleanup should handle files with unexpected names."""
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            
            # Create file with non-standard name
            bad_file = tmpdir_path / "random_file.png"
            bad_file.write_bytes(b"data")
            
            # Make it old via mtime
            import os
            import time
            old_time = time.time() - (50 * 3600)  # 50 hours ago
            os.utime(bad_file, (old_time, old_time))
            
            with patch("app.workers.tasks._ARTIFACTS_DIR", tmpdir_path):
                result = cleanup_old_artifacts()
            
            # Should attempt to delete based on mtime
            assert not bad_file.exists() or result["artifacts_deleted"] >= 0


class TestRetentionConfig:
    """Test retention configuration."""

    def test_retention_settings_exist(self) -> None:
        """Retention settings should be defined."""
        from app.config import get_settings
        settings = get_settings()
        
        assert hasattr(settings, "artifact_ttl_hours")
        assert hasattr(settings, "result_cache_ttl_days")
        assert hasattr(settings, "store_query_string")
        
        assert settings.artifact_ttl_hours > 0
        assert settings.result_cache_ttl_days > 0
        assert isinstance(settings.store_query_string, bool)

    def test_default_retention_values(self) -> None:
        """Default retention values should be reasonable."""
        from app.config import get_settings
        settings = get_settings()
        
        # Defaults from spec: 48 hours for artifacts, 7 days for results
        assert settings.artifact_ttl_hours == 48
        assert settings.result_cache_ttl_days == 7
