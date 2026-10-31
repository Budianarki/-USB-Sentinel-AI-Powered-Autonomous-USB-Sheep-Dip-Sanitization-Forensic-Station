"""Filesystem security validation and symlink traversal defense (Layer 1 & Layer 2).

Enforces:
- Supported filesystem whitelist (vfat, exfat, ext4, ntfs, etc.)
- Symlink containment within mount point
- Detection and mitigation of directory traversal via symlinks
"""

from pathlib import Path

SUPPORTED_FILESYSTEMS = {
    "vfat",
    "fat",
    "fat32",
    "fat16",
    "exfat",
    "ext2",
    "ext3",
    "ext4",
    "ntfs",
    "iso9660",
}


def is_filesystem_supported(fstype: str | None) -> bool:
    """Validate whether detected filesystem is on the approved whitelist."""
    if not fstype:
        return False
    clean = fstype.strip().lower()
    return clean in SUPPORTED_FILESYSTEMS


def validate_path_safety(path: Path, mount_point: Path) -> tuple[bool, list[str]]:
    """Verify that a path on the mounted USB device does not escape the mount point.

    Protects against symlink traversal attacks (e.g. symlink pointing to /etc/shadow or /).
    Returns (is_safe, flags).
    """
    flags: list[str] = []
    resolved_mount = mount_point.resolve()

    # 1. Symlink inspection
    if path.is_symlink():
        flags.append("symlink_detected")
        try:
            resolved_target = path.resolve()
            # Verify if target lives within mount point
            if not resolved_target.is_relative_to(resolved_mount):
                flags.append("symlink_escapes_mount")
                return False, flags
        except (OSError, RuntimeError) as exc:
            # Broken symlink, cyclic link, or resolution error
            flags.append(f"symlink_resolution_error: {exc}")
            return False, flags

    # 2. General path containment check
    try:
        resolved_path = path.resolve()
        if not resolved_path.is_relative_to(resolved_mount):
            flags.append("path_escapes_mount")
            return False, flags
    except (OSError, RuntimeError) as exc:
        flags.append(f"path_resolution_error: {exc}")
        return False, flags

    return True, flags

