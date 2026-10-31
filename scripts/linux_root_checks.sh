#!/usr/bin/env bash
# ==============================================================================
# USB Sentinel - Linux Native Root / Kernel Integration Checks
# ==============================================================================
# This script executes privileged tests required for Checkpoint 1B / Phase 1 closing:
# 1. Creates a raw 32MB disk image and formats with mkfs.vfat (FAT32)
# 2. Attaches image to a loop block device (losetup -fP)
# 3. Mounts via LinuxUdevSource production flags: -o ro,noexec,nosuid,nodev
# 4. Verifies /proc/mounts strictly contains ro, noexec, nosuid, nodev (Invariant 8)
# 5. Tests kernel-level execution prevention (noexec)
# 6. Tests symlink mount escape and path traversal rejection via validate_path_safety
# 7. Executes Phase 1 End-to-End suite in IoT mode on the mounted loop device
# 8. Guaranteed cleanup on exit (trap cleanup EXIT INT TERM)
# ==============================================================================

set -euo pipefail

# 1. Ensure running as root
if [ "$EUID" -ne 0 ]; then
    echo "[!] ERROR: This script must be executed with root privileges."
    echo "    Usage: sudo bash scripts/linux_root_checks.sh"
    exit 1
fi

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMG_FILE="/tmp/sentinel_vfat_test.img"
MOUNT_DIR="/mnt/sentinel_loop_test"
LOOP_DEV=""

echo "===================================================================="
echo "           USB SENTINEL - LINUX ROOT KERNEL CHECKS"
echo "===================================================================="
echo "[*] Working directory: ${PROJECT_DIR}"

# 2. Cleanup function
cleanup() {
    echo ""
    echo "[*] Cleaning up privileged resources..."
    if mountpoint -q "${MOUNT_DIR}" 2>/dev/null; then
        echo "  - Unmounting ${MOUNT_DIR}..."
        umount -f "${MOUNT_DIR}" || true
    fi
    if [ -n "${LOOP_DEV}" ]; then
        echo "  - Detaching loop device ${LOOP_DEV}..."
        losetup -d "${LOOP_DEV}" 2>/dev/null || true
    fi
    if [ -f "${IMG_FILE}" ]; then
        echo "  - Removing temporary image file ${IMG_FILE}..."
        rm -f "${IMG_FILE}"
    fi
    if [ -d "${MOUNT_DIR}" ]; then
        rmdir "${MOUNT_DIR}" 2>/dev/null || true
    fi
    echo "[+] Cleanup complete."
}
trap cleanup EXIT INT TERM

# 3. Verify loop module and mkfs.vfat
echo "[*] Checking loop module and mkfs.vfat..."
modprobe loop || true
if ! command -v mkfs.vfat >/dev/null 2>&1; then
    echo "[!] ERROR: mkfs.vfat utility not found. Install via: apt install dosfstools"
    exit 1
fi

# 4. Create image and format vfat
echo "[*] Creating 32MB raw test image..."
dd if=/dev/zero of="${IMG_FILE}" bs=1M count=32 status=none
echo "[*] Formatting as VFAT (FAT32)..."
mkfs.vfat -F 32 -n "SENTINEL" "${IMG_FILE}" >/dev/null

# 5. Attach loop device
echo "[*] Attaching image to loop device..."
LOOP_DEV=$(losetup -fP --show "${IMG_FILE}")
echo "[+] Attached: ${LOOP_DEV}"

# 6. Mount with production hardened flags: ro,noexec,nosuid,nodev
echo "[*] Creating mount point ${MOUNT_DIR}..."
mkdir -p "${MOUNT_DIR}"

echo "[*] Mounting ${LOOP_DEV} on ${MOUNT_DIR} with ro,noexec,nosuid,nodev..."
mount -t vfat -o ro,noexec,nosuid,nodev "${LOOP_DEV}" "${MOUNT_DIR}"

# 7. Verify /proc/mounts contains all hardened flags
echo "[*] Verifying /proc/mounts flags..."
MOUNT_ENTRY=$(grep "${MOUNT_DIR}" /proc/mounts || true)
if [ -z "${MOUNT_ENTRY}" ]; then
    echo "[!] FAILED: ${MOUNT_DIR} not found in /proc/mounts!"
    exit 1
fi
echo "  Found entry: ${MOUNT_ENTRY}"

for FLAG in ro noexec nosuid nodev; do
    if echo "${MOUNT_ENTRY}" | grep -q "${FLAG}"; then
        echo "  [OK] Flag present: ${FLAG}"
    else
        echo "  [!] FAILED: Required flag '${FLAG}' is missing in mount options!"
        exit 1
    fi
done

# 8. Test kernel noexec enforcement
echo "[*] Testing kernel noexec enforcement..."
# To create an executable file, remount rw briefly, add script, remount ro
mount -o remount,rw "${MOUNT_DIR}"
cat << 'EOF' > "${MOUNT_DIR}/test_exec.sh"
#!/bin/sh
echo "SHOULD_NOT_EXECUTE"
EOF
chmod +x "${MOUNT_DIR}/test_exec.sh"
mount -o remount,ro,noexec,nosuid,nodev "${MOUNT_DIR}"

if "${MOUNT_DIR}/test_exec.sh" 2>/dev/null; then
    echo "[!] FAILED: Script executed on noexec filesystem!"
    exit 1
else
    echo "  [OK] Execution blocked on mounted partition (Permission denied as expected)."
fi

# 9. Test symlink escape and path traversal rejection via validate_path_safety
echo "[*] Testing symlink mount escape & traversal validation in Python..."
cd "${PROJECT_DIR}"
PYTHON_BIN="${PROJECT_DIR}/.venv/bin/python"
if [ ! -f "${PYTHON_BIN}" ]; then
    PYTHON_BIN="python3"
fi

"${PYTHON_BIN}" - << 'PYEOF'
import sys
from pathlib import Path
from sentinel.guard.filesystem import validate_path_safety

mount_pt = Path("/mnt/sentinel_loop_test")
host_secret = Path("/etc/passwd")

# Create a mock symlink in /tmp pointing outside mount
tmp_link = Path("/tmp/sentinel_evil_symlink.txt")
try:
    if tmp_link.exists() or tmp_link.is_symlink():
        tmp_link.unlink()
    tmp_link.symlink_to(host_secret)
    is_safe, flags = validate_path_safety(tmp_link, mount_pt)
    assert is_safe is False, "Expected symlink outside mount to be rejected!"
    assert "symlink_escapes_mount" in flags
    print("  [OK] validate_path_safety correctly blocked symlink escaping mount point.")
finally:
    if tmp_link.is_symlink() or tmp_link.exists():
        tmp_link.unlink()

# Traversal path test
traversal_path = mount_pt / ".." / "etc" / "passwd"
is_safe_trav, flags_trav = validate_path_safety(traversal_path, mount_pt)
assert is_safe_trav is False, "Expected path traversal to be rejected!"
assert "path_escapes_mount" in flags_trav
print("  [OK] validate_path_safety correctly blocked directory traversal.")
PYEOF

# 10. Run End-to-End IoT test suite on the loop mount
echo "[*] Running Phase 1 E2E IoT test suite on mounted filesystem..."
export SENTINEL_TEST_MOUNT="${MOUNT_DIR}"
"${PYTHON_BIN}" -m pytest -v tests/integration/test_phase1_e2e_iot.py

echo ""
echo "===================================================================="
echo "[+] ALL LINUX ROOT KERNEL CHECKS PASSED SUCCESSFULLY!"
echo "===================================================================="
