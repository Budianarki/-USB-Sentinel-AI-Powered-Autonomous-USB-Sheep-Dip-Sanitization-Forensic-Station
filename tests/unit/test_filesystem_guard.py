"""Unit tests for filesystem whitelist and symlink traversal defense."""

from pathlib import Path

import pytest

from sentinel.guard.filesystem import is_filesystem_supported, validate_path_safety


def test_supported_filesystems_whitelisted() -> None:
    # Default whitelist: only vfat, fat32, exfat are allowed
    for fs in ["vfat", "VFAT", "exfat", "fat32", "fat16", "fat"]:
        assert is_filesystem_supported(fs) is True

    # ntfs, ext4, ext3, iso9660 rejected by default
    for dangerous_fs in ["ext4", "ext3", "ext2", "ntfs", "iso9660"]:
        assert is_filesystem_supported(dangerous_fs) is False

    # Unsupported filesystems rejected
    invalid_fs: list[str | None] = ["btrfs", "zfs", "nfs", "cifs", "hfsplus", None, ""]
    for inv in invalid_fs:
        assert is_filesystem_supported(inv) is False

    # Explicit configuration can opt into ntfs and ext4
    custom_whitelist = ["vfat", "exfat", "ntfs", "ext4"]
    assert is_filesystem_supported("ntfs", allowed_filesystems=custom_whitelist) is True
    assert is_filesystem_supported("ext4", allowed_filesystems=custom_whitelist) is True
    assert is_filesystem_supported("btrfs", allowed_filesystems=custom_whitelist) is False


def test_regular_file_within_mount_is_safe(tmp_path: Path) -> None:
    mount_dir = tmp_path / "usb_mount"
    mount_dir.mkdir()
    clean_file = mount_dir / "docs" / "hello.txt"
    clean_file.parent.mkdir()
    clean_file.write_text("safe content")

    is_safe, flags = validate_path_safety(clean_file, mount_dir)
    assert is_safe is True
    assert flags == []


def test_symlink_escaping_mount_point_flagged_unsafe(tmp_path: Path) -> None:
    mount_dir = tmp_path / "usb_mount"
    mount_dir.mkdir()

    outside_dir = tmp_path / "host_sensitive"
    outside_dir.mkdir()
    secret_file = outside_dir / "secret.txt"
    secret_file.write_text("password123")

    symlink_file = mount_dir / "evil_link.txt"
    try:
        symlink_file.symlink_to(secret_file)
    except OSError:
        pytest.skip("Symlink creation requires privileges or unsupported on this environment")

    is_safe, flags = validate_path_safety(symlink_file, mount_dir)
    assert is_safe is False
    assert "symlink_detected" in flags
    assert "symlink_escapes_mount" in flags


def test_symlink_mock_traversal(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test symlink traversal logic using path resolution mocks."""
    mount_dir = tmp_path / "usb_mount"
    mount_dir.mkdir()
    fake_link = mount_dir / "mock_link.txt"
    fake_target = tmp_path / "host_sensitive" / "passwords.txt"

    monkeypatch.setattr(Path, "is_symlink", lambda self: self == fake_link)
    monkeypatch.setattr(Path, "resolve", lambda self: fake_target if self == fake_link else self)

    is_safe, flags = validate_path_safety(fake_link, mount_dir)
    assert is_safe is False
    assert "symlink_detected" in flags
    assert "symlink_escapes_mount" in flags
