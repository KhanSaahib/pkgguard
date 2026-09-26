"""Heuristic detection rules for malicious package install-time behavior.

Every rule is a small, dependency-free regex or AST-lite check. Rules are
intentionally conservative (favor precision) and are meant to be combined:
a single "reads network" signal is low severity, but "reads a secret AND
makes a network call in the same file" is scored much higher, mirroring
how real supply-chain worms (e.g. credential-harvesting npm postinstall
scripts) chain multiple capabilities together.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


@dataclass
class Finding:
    rule_id: str
    severity: Severity
    file: str
    line: int
    description: str
    snippet: str = ""


# ---------------------------------------------------------------------------
# Lifecycle script rules (package.json scripts.*, setup.py install-time code)
# ---------------------------------------------------------------------------

LIFECYCLE_SCRIPT_KEYS = (
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "postuninstall",
    "prepare",
    "prepublish",
    "prepublishOnly",
)

_SHELL_DOWNLOAD_EXEC = re.compile(
    r"(curl|wget)\s+[^|]*\|\s*(sh|bash|zsh)\b"
    r"|(base64\s+-d|base64\s+--decode)[^|]*\|\s*(sh|bash)\b"
    r"|powershell(\.exe)?\s+.*(-enc|-EncodedCommand)\b",
    re.IGNORECASE,
)

_NODE_INLINE_EVAL = re.compile(r"node\s+(-e|--eval)\s", re.IGNORECASE)


def scan_lifecycle_scripts(scripts: dict, file_label: str) -> list[Finding]:
    findings: list[Finding] = []
    for key, cmd in (scripts or {}).items():
        if key not in LIFECYCLE_SCRIPT_KEYS or not isinstance(cmd, str):
            continue
        if _SHELL_DOWNLOAD_EXEC.search(cmd):
            findings.append(
                Finding(
                    rule_id="LIFECYCLE_REMOTE_EXEC",
                    severity=Severity.CRITICAL,
                    file=file_label,
                    line=1,
                    description=(
                        f"'{key}' script downloads and pipes remote content "
                        "directly into a shell/decoder"
                    ),
                    snippet=cmd[:200],
                )
            )
        if _NODE_INLINE_EVAL.search(cmd):
            findings.append(
                Finding(
                    rule_id="LIFECYCLE_INLINE_EVAL",
                    severity=Severity.HIGH,
                    file=file_label,
                    line=1,
                    description=f"'{key}' script runs inline Node code via -e/--eval",
                    snippet=cmd[:200],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Source-level rules shared across JS/TS and Python
# ---------------------------------------------------------------------------

_SECRET_ENV_PATTERNS = re.compile(
    r"(AWS_(SECRET|ACCESS_KEY|SESSION_TOKEN)\w*"
    r"|NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY"
    r"|DATABASE_URL|PRIVATE_KEY|SLACK_TOKEN|STRIPE_(SECRET|API)_KEY)",
    re.IGNORECASE,
)

_SENSITIVE_FILE_PATTERNS = re.compile(
    r"\.ssh[/\\](id_rsa|id_ed25519|known_hosts)"
    r"|\.aws[/\\]credentials"
    r"|\.npmrc"
    r"|\.netrc"
    r"|\.gnupg"
    r"|Login Data" # common Chromium credential-store filename used by stealers
    r"|shadow\b",
    re.IGNORECASE,
)

_OBFUSCATION_EVAL = re.compile(r"\beval\s*\(|new\s+Function\s*\(")
_OBFUSCATION_DECODE_CHAIN = re.compile(
    r"(atob|Buffer\.from\([^)]*['\"]base64['\"]\)|base64\.b64decode)\s*\("
)

_NETWORK_JS = re.compile(
    r"require\(['\"]https?['\"]\)|fetch\s*\(|axios\.(get|post)\s*\(|"
    r"new\s+XMLHttpRequest\s*\(|net\.connect\s*\("
)
_NETWORK_PY = re.compile(
    r"requests\.(get|post)\s*\(|urllib\.request\.urlopen\s*\(|socket\.socket\s*\("
)

_SHELL_EXEC_JS = re.compile(
    r"require\(['\"]child_process['\"]\).*?\.(exec|execSync|spawn)\s*\("
    r"|\.(exec|execSync)\s*\("
)
_SHELL_EXEC_PY = re.compile(
    r"os\.system\s*\(|subprocess\.(Popen|call|run|check_output)\s*\([^)]*shell\s*=\s*True"
)

_WORM_WRITE_NODE_MODULES = re.compile(
    r"writeFileSync\s*\([^)]*node_modules(?!/pkgguard)"
)
_WORM_NPM_PUBLISH = re.compile(r"npm(-cli\.js)?\s+publish\b")


def _find_line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def scan_js_source(text: str, file_label: str) -> list[Finding]:
    findings: list[Finding] = []
    has_secret = _SECRET_ENV_PATTERNS.search(text) or _SENSITIVE_FILE_PATTERNS.search(text)
    has_network = _NETWORK_JS.search(text)

    for m in _OBFUSCATION_EVAL.finditer(text):
        findings.append(
            Finding(
                "OBFUSCATION_EVAL", Severity.MEDIUM, file_label,
                _find_line(text, m.start()),
                "Use of eval()/Function() constructor, common in obfuscated payloads",
                text[max(0, m.start() - 20): m.start() + 40],
            )
        )
    for m in _OBFUSCATION_DECODE_CHAIN.finditer(text):
        findings.append(
            Finding(
                "OBFUSCATION_DECODE", Severity.MEDIUM, file_label,
                _find_line(text, m.start()),
                "Base64/atob decode chain, often used to hide payload strings",
                text[max(0, m.start() - 20): m.start() + 40],
            )
        )
    for m in _WORM_WRITE_NODE_MODULES.finditer(text):
        findings.append(
            Finding(
                "WORM_SIBLING_WRITE", Severity.CRITICAL, file_label,
                _find_line(text, m.start()),
                "Writes into another package's node_modules tree "
                "(self-propagation pattern seen in npm worm outbreaks)",
                text[max(0, m.start() - 20): m.start() + 60],
            )
        )
    for m in _WORM_NPM_PUBLISH.finditer(text):
        findings.append(
            Finding(
                "WORM_SELF_PUBLISH", Severity.CRITICAL, file_label,
                _find_line(text, m.start()),
                "Invokes 'npm publish' from within package code",
                text[max(0, m.start() - 20): m.start() + 40],
            )
        )
    if has_secret and has_network:
        m = has_secret
        findings.append(
            Finding(
                "SECRET_EXFIL_CHAIN", Severity.CRITICAL, file_label,
                _find_line(text, m.start()),
                "Reads a credential/secret and also performs outbound network "
                "calls in the same file (possible exfiltration chain)",
                text[max(0, m.start() - 20): m.start() + 40],
            )
        )
    elif has_secret:
        m = has_secret
        findings.append(
            Finding(
                "SECRET_ACCESS", Severity.LOW, file_label,
                _find_line(text, m.start()),
                "References a well-known secret env var or credential file path",
                text[max(0, m.start() - 20): m.start() + 40],
            )
        )
    for m in _SHELL_EXEC_JS.finditer(text):
        findings.append(
            Finding(
                "SHELL_EXEC", Severity.LOW, file_label,
                _find_line(text, m.start()),
                "Spawns a child process/shell command",
                text[max(0, m.start() - 20): m.start() + 40],
            )
        )
    return findings


def scan_py_source(text: str, file_label: str) -> list[Finding]:
    findings: list[Finding] = []
    has_secret = _SECRET_ENV_PATTERNS.search(text) or _SENSITIVE_FILE_PATTERNS.search(text)
    has_network = _NETWORK_PY.search(text)

    for m in re.finditer(r"\bexec\s*\(|\beval\s*\(", text):
        findings.append(
            Finding(
                "OBFUSCATION_EVAL", Severity.MEDIUM, file_label,
                _find_line(text, m.start()),
                "Use of exec()/eval(), common in obfuscated or dynamically "
                "generated malicious install code",
                text[max(0, m.start() - 20): m.start() + 40],
            )
        )
    for m in _OBFUSCATION_DECODE_CHAIN.finditer(text):
        findings.append(
            Finding(
                "OBFUSCATION_DECODE", Severity.MEDIUM, file_label,
                _find_line(text, m.start()),
                "Base64 decode chain, often used to hide payload strings",
                text[max(0, m.start() - 20): m.start() + 40],
            )
        )
    for m in _SHELL_EXEC_PY.finditer(text):
        findings.append(
            Finding(
                "SHELL_EXEC_SHELL_TRUE", Severity.HIGH, file_label,
                _find_line(text, m.start()),
                "Executes a shell command with shell=True / os.system",
                text[max(0, m.start() - 20): m.start() + 60],
            )
        )
    if has_secret and has_network:
        m = has_secret
        findings.append(
            Finding(
                "SECRET_EXFIL_CHAIN", Severity.CRITICAL, file_label,
                _find_line(text, m.start()),
                "Reads a credential/secret and also performs outbound network "
                "calls in the same file (possible exfiltration chain)",
                text[max(0, m.start() - 20): m.start() + 40],
            )
        )
    elif has_secret:
        m = has_secret
        findings.append(
            Finding(
                "SECRET_ACCESS", Severity.LOW, file_label,
                _find_line(text, m.start()),
                "References a well-known secret env var or credential file path",
                text[max(0, m.start() - 20): m.start() + 40],
            )
        )
    return findings


def scan_setup_py(text: str, file_label: str) -> list[Finding]:
    """setup.py runs at install time for sdists, so any of the general
    Python findings apply, plus a specific check for custom cmdclass hooks
    which is the classic PyPI install-time-code-execution vector."""
    findings = scan_py_source(text, file_label)
    if re.search(r"cmdclass\s*=\s*\{", text) and re.search(r"class\s+\w+\(install\)", text):
        findings.append(
            Finding(
                "SETUP_CUSTOM_INSTALL_CMD", Severity.HIGH, file_label, 1,
                "Overrides the setuptools 'install' command class - runs "
                "arbitrary code during 'pip install' before any sandboxing",
            )
        )
    return findings
