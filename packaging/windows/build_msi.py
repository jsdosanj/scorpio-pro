"""Build a Windows MSI installer for Scorpio Pro using cx_Freeze."""

from __future__ import annotations

import sys
from pathlib import Path

try:
    from cx_Freeze import setup, Executable  # type: ignore[import]
except ImportError:
    print("cx_Freeze is required. Install with:  pip install cx_Freeze")
    sys.exit(1)

REPO_ROOT = Path(__file__).parent.parent.parent
VERSION = "1.0.0"
APP_NAME = "ScorpioPro"

# Include all reporting templates
include_files = [
    (
        str(REPO_ROOT / "scorpio_pro" / "reporting" / "templates"),
        "scorpio_pro/reporting/templates",
    ),
    (str(REPO_ROOT / "example_scope.yaml"), "example_scope.yaml"),
]

build_exe_options = {
    "packages": [
        "scorpio_pro",
        "scorpio_pro.core",
        "scorpio_pro.scanners",
        "scorpio_pro.compliance",
        "scorpio_pro.config",
        "scorpio_pro.reporting",
        "scorpio_pro.utils",
        "click",
        "psutil",
        "yaml",
        "jinja2",
        "rich",
        "colorama",
        "cryptography",
        "requests",
        "paramiko",
    ],
    "include_files": include_files,
    "excludes": ["tkinter"],
    "optimize": 2,
}

bdist_msi_options = {
    "upgrade_code": "{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}",
    "add_to_path": True,
    "initial_target_dir": rf"[ProgramFilesFolder]\{APP_NAME}",
    "summary_data": {
        "author": "jsdosanj",
        "comments": "State-of-the-art penetration testing and security auditing tool",
    },
}

executables = [
    Executable(
        script=str(REPO_ROOT / "scorpio_pro" / "cli.py"),
        target_name="scorpio-pro.exe",
        base=None,  # Console application
        icon=None,
    )
]

setup(
    name=APP_NAME,
    version=VERSION,
    description="Scorpio Pro — Penetration Testing & Security Auditing",
    author="jsdosanj",
    options={
        "build_exe": build_exe_options,
        "bdist_msi": bdist_msi_options,
    },
    executables=executables,
)

if __name__ == "__main__":
    # Run with:  python packaging/windows/build_msi.py bdist_msi
    print(f"Run: python {__file__} bdist_msi")
    print("Output will be in the dist/ directory.")
