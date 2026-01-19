#!/usr/bin/env python3

import os
import re
import argparse
import sys
from patterns import PATTERNS

IGNORED_DIRECTORIES = {
    ".git", ".svn", ".hg", "__pycache__", "node_modules",
    "venv", ".venv", "env", ".env", "dist", "build"
}

ALLOWED_EXTENSIONS = {
    ".py", ".js", ".ts", ".java", ".go", ".rb", ".php",
    ".env", ".txt", ".yaml", ".yml", ".json", ".ini"
}

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB


def mask_secret(secret: str, visible: int = 4) -> str:
    if len(secret) <= visible * 2:
        return "*" * len(secret)
    return secret[:visible] + "*" * (len(secret) - (visible * 2)) + secret[-visible:]


def is_binary_file(filepath: str) -> bool:
    try:
        with open(filepath, "rb") as f:
            return b"\0" in f.read(1024)
    except Exception:
        return True


def should_scan_file(filepath: str) -> bool:
    _, ext = os.path.splitext(filepath)
    if ext and ext.lower() not in ALLOWED_EXTENSIONS:
        return False
    try:
        if os.path.getsize(filepath) > MAX_FILE_SIZE:
            return False
    except Exception:
        return False
    if is_binary_file(filepath):
        return False
    return True


def scan_file(filepath: str):
    findings = []
    if not should_scan_file(filepath):
        return findings

    try:
        with open(filepath, "r", errors="ignore") as f:
            for lineno, line in enumerate(f, start=1):
                for secret_type, pattern in PATTERNS.items():
                    for match in pattern.findall(line):
                        findings.append({
                                            "file": filepath,
                                            "line": lineno,
                                            "type": secret_type,
                                            "raw_value": match,
                                            "masked_value": mask_secret(match),
                                        })

    except Exception:
        pass

    return findings


def scan_directory(path: str):
    results = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRECTORIES]
        for file in files:
            full_path = os.path.join(root, file)
            results.extend(scan_file(full_path))
    return results


def main():
    parser = argparse.ArgumentParser(description="Secret & API Key Detector (Blue Team Tool)")
    parser.add_argument("path", help="Directory to scan")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print("[-] Path does not exist")
        sys.exit(2)

    findings = scan_directory(args.path)

    if not findings:
        print("[+] No secrets detected")
        sys.exit(0)

    print("[!] Potential secrets detected:\n")
    for f in findings:
        print(f"{f['file']}:{f['line']} | {f['type']} | {f['value']}")

    sys.exit(1)


if __name__ == "__main__":
    main()
