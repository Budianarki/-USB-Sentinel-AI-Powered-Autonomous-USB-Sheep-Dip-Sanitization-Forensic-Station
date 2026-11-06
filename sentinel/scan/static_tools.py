"""Static analysis tools for PE, Office, PDF, and scripts (Layer 2).

Performs read-only inspection of file contents:
- PE headers and section entropy (pefile or pure-python parser)
- Office VBA macro detection (oletools or zip inspection)
- PDF structure and action inspection (pdfid or regex token search)
- Script obfuscation detection
"""

import re
import struct
from pathlib import Path
from typing import Any

from sentinel.scan.filetype import calculate_entropy


def analyze_pe(file_path: Path) -> dict[str, Any]:
    """Inspect Windows Portable Executable (PE) headers and sections."""
    summary: dict[str, Any] = {
        "is_pe": False,
        "sections": [],
        "packed": False,
        "suspicious_imports": [],
        "flags": [],
    }

    try:
        data = file_path.read_bytes()
        if len(data) < 64 or not data.startswith(b"MZ"):
            return summary

        summary["is_pe"] = True
        # Read PE header offset at 0x3C (e_lfanew)
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            return summary

        num_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        opt_hdr_size = struct.unpack_from("<H", data, e_lfanew + 20)[0]
        sec_start = e_lfanew + 24 + opt_hdr_size

        for i in range(min(num_sections, 32)):
            offset = sec_start + (i * 40)
            if offset + 40 > len(data):
                break
            sec_name = data[offset : offset + 8].rstrip(b"\x00").decode("latin1", errors="ignore")
            raw_size = struct.unpack_from("<I", data, offset + 16)[0]
            raw_ptr = struct.unpack_from("<I", data, offset + 20)[0]

            sec_data = (
                data[raw_ptr : raw_ptr + raw_size] if raw_ptr + raw_size <= len(data) else b""
            )
            ent = calculate_entropy(sec_data) if sec_data else 0.0

            summary["sections"].append({"name": sec_name, "entropy": ent, "size": raw_size})

            # Entropy > 7.2 in section indicates packing or encryption
            if ent > 7.2 and raw_size > 4096:
                summary["packed"] = True
                if "pe_packed" not in summary["flags"]:
                    summary["flags"].append("pe_packed")

        # Check for dangerous API string imports
        dangerous_apis = [
            b"VirtualAlloc",
            b"WriteProcessMemory",
            b"CreateRemoteThread",
            b"URLDownloadToFile",
            b"WinExec",
            b"ShellExecute",
        ]
        for api in dangerous_apis:
            if api in data:
                summary["suspicious_imports"].append(api.decode())

        if summary["suspicious_imports"]:
            summary["flags"].append("pe_suspicious_apis")

    except Exception as exc:  # noqa: BLE001
        summary["flags"].append(f"pe_parse_error: {exc}")

    return summary


def analyze_office(file_path: Path) -> dict[str, Any]:
    """Inspect Office document (DOCX/XLSX/PPTX or legacy OLE) for VBA macros."""
    summary: dict[str, Any] = {
        "has_macros": False,
        "autoexec": False,
        "flags": [],
    }

    try:
        import zipfile

        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path, "r") as zf:
                names = zf.namelist()
                vba_files = [n for n in names if "vbaProject.bin" in n or n.endswith(".vba")]
                if vba_files:
                    summary["has_macros"] = True
                    summary["flags"].append("office_macro_present")
                    # Read vba binary for auto-exec keywords
                    vba_bytes = zf.read(vba_files[0])
                    autoexec_keywords = [
                        b"AutoExec",
                        b"AutoOpen",
                        b"Document_Open",
                        b"Workbook_Open",
                        b"AutoClose",
                    ]
                    if any(kw in vba_bytes for kw in autoexec_keywords):
                        summary["autoexec"] = True
                        summary["flags"].append("office_macro_autoexec")
        else:
            # Check legacy OLE
            raw = file_path.read_bytes()
            if b"\x00Attribut" in raw or b"AutoOpen" in raw or b"Document_Open" in raw:
                summary["has_macros"] = True
                summary["flags"].append("office_macro_present")
                if b"AutoOpen" in raw or b"Document_Open" in raw:
                    summary["autoexec"] = True
                    summary["flags"].append("office_macro_autoexec")

    except Exception as exc:  # noqa: BLE001
        summary["flags"].append(f"office_parse_error: {exc}")

    return summary


def analyze_pdf(file_path: Path) -> dict[str, Any]:
    """Inspect PDF document for embedded JavaScript or automatic execution triggers."""
    summary: dict[str, Any] = {
        "has_javascript": False,
        "has_openaction": False,
        "has_launch": False,
        "flags": [],
    }

    try:
        raw = file_path.read_bytes()
        if re.search(rb"/JavaScript|/JS\b", raw):
            summary["has_javascript"] = True
            summary["flags"].append("pdf_javascript")

        if re.search(rb"/OpenAction\b", raw):
            summary["has_openaction"] = True
            summary["flags"].append("pdf_openaction")

        if re.search(rb"/Launch\b", raw):
            summary["has_launch"] = True
            summary["flags"].append("pdf_launch_action")

    except Exception as exc:  # noqa: BLE001
        summary["flags"].append(f"pdf_parse_error: {exc}")

    return summary


def analyze_script(file_path: Path) -> dict[str, Any]:
    """Inspect shell / powershell / python / batch scripts for dangerous obfuscation."""
    summary: dict[str, Any] = {
        "obfuscated": False,
        "suspicious_patterns": [],
        "flags": ["script_detected"],
    }

    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
        lower = text.lower()

        patterns = [
            ("invoke-expression", "powershell_iex"),
            ("iex ", "powershell_iex"),
            ("-encodedcommand", "powershell_encoded"),
            ("-enc ", "powershell_encoded"),
            ("frombase64string", "base64_decode"),
            ("downloadstring", "remote_download"),
            ("eval(", "eval_invocation"),
            ("certutil -decode", "certutil_decode"),
            ("wscript.shell", "wscript_shell_invocation"),
            ("activexobject", "activex_creation"),
            ("msxml2.xmlhttp", "remote_downloader"),
            ("winhttprequest", "remote_downloader"),
            ("bitsadmin", "bitsadmin_downloader"),
            ("reg add", "registry_persistence"),
            ("netsh advfirewall", "firewall_tampering"),
            ("attrib +h", "file_hiding"),
            ("amsiutils", "amsi_bypass"),
            ("tcpclient", "reverse_shell"),
        ]

        for pattern, flag in patterns:
            if pattern in lower:
                summary["suspicious_patterns"].append(pattern)
                if flag not in summary["flags"]:
                    summary["flags"].append(flag)

        if len(summary["suspicious_patterns"]) >= 2:
            summary["obfuscated"] = True

    except Exception as exc:  # noqa: BLE001
        summary["flags"].append(f"script_parse_error: {exc}")

    return summary


def analyze_lnk(file_path: Path) -> dict[str, Any]:
    """Inspect Windows Shell Link (.lnk) files for command invocation."""
    summary: dict[str, Any] = {
        "is_lnk": True,
        "has_command": False,
        "flags": ["windows_shortcut_detected"],
    }
    try:
        raw = file_path.read_bytes()
        lower = raw.lower()
        commands = [b"powershell", b"cmd.exe", b"wscript", b"cscript", b"mshta", b"rundll32", b"regsvr32", b"bitsadmin"]
        for cmd in commands:
            if cmd in lower:
                summary["has_command"] = True
                cmd_str = cmd.decode("ascii")
                summary["flags"].append(f"lnk_invokes_{cmd_str}")
    except Exception as exc:  # noqa: BLE001
        summary["flags"].append(f"lnk_parse_error: {exc}")
    return summary


def analyze_autorun(file_path: Path) -> dict[str, Any]:
    """Inspect autorun.inf files for automatic execution triggers."""
    summary: dict[str, Any] = {
        "is_autorun": True,
        "autoexec": False,
        "flags": ["autorun_inf_present"],
    }
    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore").lower()
        triggers = ["open=", "shellexecute=", "shell\\open\\command=", "shell\\explore\\command="]
        for trig in triggers:
            if trig in text:
                summary["autoexec"] = True
                summary["flags"].append("autorun_autoexec_trigger")
                break
    except Exception as exc:  # noqa: BLE001
        summary["flags"].append(f"autorun_parse_error: {exc}")
    return summary
