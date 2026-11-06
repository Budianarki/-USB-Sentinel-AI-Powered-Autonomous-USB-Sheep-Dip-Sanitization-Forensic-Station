"""Subprocess worker executing static file parsers in isolation (Layer 2).

Invoked by static_runner to prevent crashes, memory leaks, or hangs in host process.
"""

import argparse
import json
import sys
from pathlib import Path

from sentinel.scan.filetype import detect_file_type
from sentinel.scan.static_tools import (
    analyze_office,
    analyze_pdf,
    analyze_pe,
    analyze_script,
)


def run_worker() -> None:
    parser = argparse.ArgumentParser(description="Isolated static analysis worker")
    parser.add_argument("--file", required=True, help="Path to temporary file")
    parser.add_argument(
        "--tool", required=True, choices=["all", "type", "pe", "office", "pdf", "script"]
    )
    parser.add_argument("--filename", default="", help="Original filename for extension context")
    args = parser.parse_args()

    file_path = Path(args.file)
    if not file_path.exists():
        sys.stderr.write(f"File not found: {file_path}\n")
        sys.exit(2)

    data = file_path.read_bytes()
    filename = args.filename or file_path.name

    result: dict = {
        "status": "success",
        "flags": [],
        "static_summary": {},
    }

    # 1. Type detection
    type_res = detect_file_type(data[:512], filename, sample_data=data[:4096])
    result["detected_type"] = type_res.detected_type
    result["ext_mismatch"] = type_res.ext_mismatch
    result["entropy"] = type_res.entropy
    result["flags"].extend(type_res.flags)

    tool = args.tool
    # 2. Targeted or auto static analysis based on detected type
    if tool == "pe" or (tool == "all" and type_res.detected_type in ("pe", "elf")):
        pe_summary = analyze_pe(file_path)
        result["static_summary"]["pe"] = pe_summary
        result["flags"].extend(pe_summary.get("flags", []))

    if tool == "office" or (
        tool == "all" and type_res.detected_type in ("docx", "xlsx", "pptx", "ole_compound")
    ):
        office_summary = analyze_office(file_path)
        result["static_summary"]["office"] = office_summary
        result["flags"].extend(office_summary.get("flags", []))

    if tool == "pdf" or (tool == "all" and type_res.detected_type == "pdf"):
        pdf_summary = analyze_pdf(file_path)
        result["static_summary"]["pdf"] = pdf_summary
        result["flags"].extend(pdf_summary.get("flags", []))

    if tool == "script" or (tool == "all" and type_res.detected_type == "script"):
        script_summary = analyze_script(file_path)
        result["static_summary"]["script"] = script_summary
        result["flags"].extend(script_summary.get("flags", []))

    # De-duplicate flags
    result["flags"] = list(dict.fromkeys(result["flags"]))

    sys.stdout.write(json.dumps(result))
    sys.exit(0)


if __name__ == "__main__":
    run_worker()
