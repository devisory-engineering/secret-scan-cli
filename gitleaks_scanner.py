#!/usr/bin/env python3
"""CLI utility to run gitleaks on one or more local repositories and generate an HTML report."""

from __future__ import annotations

import argparse
import ctypes
import html
import json
import os
import platform
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from datetime import datetime
from pathlib import Path
from string import Template
from typing import Any
from urllib.parse import urlencode
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen, urlretrieve

GITLEAKS_VERSION = "8.18.2"
GITLEAKS_BASE_URL = "https://github.com/gitleaks/gitleaks/releases/download"
REPORT_TEMPLATE_FILENAME = "templates/DONT_MODIFY_REPORT_TEMPLATE.html"
DEFAULT_SQS_URL = "https://sqs.eu-central-1.amazonaws.com/937764685191/secrets-scan-report"
SQS_API_VERSION = "2012-11-05"
MAX_SQS_MESSAGE_BYTES = 262_144
COLOR_ENABLED = False

ANSI_RESET = "\033[0m"
ANSI_RED = "\033[31m"
ANSI_GREEN = "\033[32m"
ANSI_YELLOW = "\033[33m"
ANSI_CYAN = "\033[36m"


class ScannerError(RuntimeError):
    """Raised when scanner setup or execution fails."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Download gitleaks (if needed), scan repositories, and generate an HTML report."
        )
    )
    parser.add_argument(
        "repos_path",
        type=Path,
        help="Path to a folder containing repositories to scan.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("gitleaks_report.html"),
        help="Output report path (default: gitleaks_report.html).",
    )
    parser.add_argument(
        "--gitleaks-path",
        type=Path,
        default=None,
        help="Use an existing gitleaks binary instead of downloading one.",
    )
    parser.add_argument(
        "--no-git-history",
        action="store_true",
        help="Skip git-history scanning and only scan current working tree.",
    )
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="Colorize terminal output (default: auto).",
    )
    parser.add_argument(
        "--json-output",
        type=Path,
        default=None,
        help="Optional path to save JSON report locally.",
    )
    parser.add_argument(
        "--eng-id",
        default=None,
        help="Optional Cloudvisor customer engagement ID to include in findings JSON.",
    )
    return parser.parse_args()


def should_use_color(color_mode: str) -> bool:
    if color_mode == "always":
        return supports_ansi_color()
    if color_mode == "never":
        return False
    return sys.stdout.isatty() and supports_ansi_color()


def _enable_windows_vt_mode() -> bool:
    if os.name != "nt":
        return True
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        if handle == 0:
            return False
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)) == 0:
            return False
        enabled = mode.value | 0x0004  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
        if kernel32.SetConsoleMode(handle, enabled) == 0:
            return False
        return True
    except Exception:
        return False


def supports_ansi_color() -> bool:
    if os.name != "nt":
        return True
    if os.environ.get("ANSICON") or os.environ.get("WT_SESSION"):
        return True
    term_program = os.environ.get("TERM_PROGRAM", "").lower()
    if term_program in {"vscode", "mintty"}:
        return True
    return _enable_windows_vt_mode()


def colorize(text: str, color_code: str) -> str:
    if not COLOR_ENABLED:
        return text
    return f"{color_code}{text}{ANSI_RESET}"


def get_gitleaks_url() -> str:
    system = platform.system().lower()
    machine = platform.machine().lower()

    if machine in {"x86_64", "amd64"}:
        arch = "x64"
    elif machine in {"arm64", "aarch64"}:
        arch = "arm64"
    else:
        raise ScannerError(f"Unsupported CPU architecture: {machine}")

    if system == "darwin":
        package = f"gitleaks_{GITLEAKS_VERSION}_darwin_{arch}.tar.gz"
    elif system == "linux":
        package = f"gitleaks_{GITLEAKS_VERSION}_linux_{arch}.tar.gz"
    elif system == "windows":
        package = f"gitleaks_{GITLEAKS_VERSION}_windows_{arch}.zip"
    else:
        raise ScannerError(f"Unsupported operating system: {system}")

    return f"{GITLEAKS_BASE_URL}/v{GITLEAKS_VERSION}/{package}"


def safe_extract_tar(tar_path: Path, destination: Path, member_name: str) -> None:
    with tarfile.open(tar_path, "r:gz") as archive:
        try:
            member = archive.getmember(member_name)
        except KeyError as exc:
            raise ScannerError(f"Expected binary '{member_name}' not found in downloaded archive") from exc
        destination_path = destination / member.name
        resolved_destination = destination.resolve()
        resolved_target = destination_path.resolve()
        if (
            resolved_destination not in resolved_target.parents
            and resolved_target != resolved_destination
        ):
            raise ScannerError("Tar archive contains unsafe path")
        try:
            archive.extract(member, destination, filter="data")
        except TypeError:
            # Python <3.12 does not support the filter argument.
            archive.extract(member, destination)


def download_file(url: str, destination: Path) -> None:
    try:
        urlretrieve(url, destination)
        return
    except HTTPError as exc:
        raise ScannerError(f"Failed to download gitleaks ({exc.code} {exc.reason})") from exc
    except URLError as exc:
        reason = getattr(exc, "reason", None)
        if isinstance(reason, ssl.SSLCertVerificationError):
            try:
                import certifi  # type: ignore
            except ImportError as import_exc:
                raise ScannerError(
                    "TLS certificate verification failed while downloading gitleaks.\n"
                    "Install Python certificates, or provide --gitleaks-path.\n"
                    "macOS fix (Framework Python): run "
                    "'/Applications/Python 3.12/Install Certificates.command'"
                ) from import_exc

            try:
                ssl_context = ssl.create_default_context(cafile=certifi.where())
                with urlopen(url, context=ssl_context) as response, destination.open("wb") as output:
                    shutil.copyfileobj(response, output)
                return
            except Exception as certifi_exc:
                raise ScannerError(
                    "TLS certificate verification failed while downloading gitleaks, "
                    "including certifi fallback. Use --gitleaks-path to continue."
                ) from certifi_exc

        raise ScannerError(f"Failed to download gitleaks: {exc}") from exc


def download_gitleaks(destination_dir: Path) -> Path:
    binary_name = "gitleaks.exe" if os.name == "nt" else "gitleaks"
    binary_path = destination_dir / binary_name

    if binary_path.exists():
        return binary_path

    url = get_gitleaks_url()
    print(colorize(f"Downloading gitleaks v{GITLEAKS_VERSION} from {url}", ANSI_CYAN))

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        suffix = ".zip" if url.endswith(".zip") else ".tar.gz"
        archive_path = tmp_path / f"gitleaks_archive{suffix}"
        download_file(url, archive_path)

        if url.endswith(".zip"):
            with zipfile.ZipFile(archive_path, "r") as archive:
                try:
                    archive.extract(binary_name, destination_dir)
                except KeyError as exc:
                    raise ScannerError(
                        f"Expected binary '{binary_name}' not found in downloaded archive"
                    ) from exc
        else:
            safe_extract_tar(archive_path, destination_dir, binary_name)

    if os.name != "nt":
        binary_path.chmod(0o755)

    return binary_path


def load_findings(report_path: Path) -> list[dict[str, Any]]:
    if not report_path.exists():
        return []

    try:
        with report_path.open("r", encoding="utf-8") as file:
            data = json.load(file)
            return data if isinstance(data, list) else []
    except json.JSONDecodeError:
        return []
    finally:
        report_path.unlink(missing_ok=True)


def run_gitleaks_scan(
    gitleaks_path: Path,
    repo_path: Path,
    *,
    no_git: bool,
    report_path: Path,
) -> list[dict[str, Any]]:
    cmd = [
        str(gitleaks_path),
        "detect",
        "--source",
        str(repo_path),
        "--report-format",
        "json",
        "--report-path",
        str(report_path),
    ]
    if no_git:
        cmd.append("--no-git")

    result = subprocess.run(cmd, capture_output=True, text=True)

    # gitleaks exit codes:
    # 0: no leaks, 1: leaks found, >1: execution error.
    if result.returncode > 1:
        stderr = result.stderr.strip() or "Unknown gitleaks error"
        raise ScannerError(f"gitleaks failed for '{repo_path}': {stderr}")

    return load_findings(report_path)


def scan_repo(gitleaks_path: Path, repo_path: Path, include_git_history: bool) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []

    if include_git_history:
        history_report = Path(f"scan_{repo_path.name}_git.json")
        findings.extend(
            run_gitleaks_scan(
                gitleaks_path,
                repo_path,
                no_git=False,
                report_path=history_report,
            )
        )

    working_tree_report = Path(f"scan_{repo_path.name}_nogit.json")
    no_git_findings = run_gitleaks_scan(
        gitleaks_path,
        repo_path,
        no_git=True,
        report_path=working_tree_report,
    )
    for finding in no_git_findings:
        if not finding.get("Commit"):
            finding["Commit"] = "Uncommitted"
        finding["CommitAuthor"] = "Uncommitted"
    findings.extend(no_git_findings)

    for finding in findings:
        finding["repo"] = repo_path.name
        if finding.get("CommitAuthor"):
            continue
        author = str(finding.get("Author") or "").strip()
        email = str(finding.get("Email") or "").strip()
        if author and email:
            finding["CommitAuthor"] = f"{author} <{email}>"
        elif author:
            finding["CommitAuthor"] = author
        elif finding.get("Commit") and finding.get("Commit") != "Uncommitted":
            finding["CommitAuthor"] = "N/A"
        else:
            finding["CommitAuthor"] = "Uncommitted"

    return findings


def redact_secret(secret: str) -> str:
    if not secret:
        return ""
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}{'*' * (len(secret) - 8)}{secret[-4:]}"


def _escape(value: Any) -> str:
    return html.escape(str(value if value is not None else "N/A"))


def load_report_template() -> Template:
    template_path = Path(__file__).resolve().parent / REPORT_TEMPLATE_FILENAME
    if not template_path.exists():
        raise ScannerError(f"Report template file not found: {template_path}")
    return Template(template_path.read_text(encoding="utf-8"))


def generate_html_report(all_findings: list[dict[str, Any]], repos_path: Path, output_path: Path) -> Path:
    scanned_repos = len(set(f.get("repo") for f in all_findings if f.get("repo")))
    secret_types = len(set(f.get("RuleID") for f in all_findings if f.get("RuleID")))

    rows: list[str] = []
    for index, finding in enumerate(all_findings, start=1):
        commit = finding.get("Commit")
        if commit and commit != "Uncommitted":
            commit = str(commit)[:8]
        else:
            commit = "Uncommitted"
        commit_author = finding.get("CommitAuthor", "N/A")

        secret = finding.get("Secret") or finding.get("Match") or ""

        row = """
        <tr>
            <td>{index}</td>
            <td>{repo}</td>
            <td>{file_path}</td>
            <td>{line}</td>
            <td class="high">{rule_id}</td>
            <td class="description">{description}</td>
            <td><code class="code redacted">{redacted_secret}</code></td>
            <td>{commit}</td>
            <td>{commit_author}</td>
        </tr>
        """.format(
            index=_escape(index),
            repo=_escape(finding.get("repo", "N/A")),
            file_path=_escape(finding.get("File", "N/A")),
            line=_escape(finding.get("StartLine", "N/A")),
            rule_id=_escape(finding.get("RuleID", "N/A")),
            description=_escape(finding.get("Description", "N/A")),
            redacted_secret=_escape(redact_secret(str(secret))),
            commit=_escape(commit),
            commit_author=_escape(commit_author),
        )
        rows.append(row)

    html_report = load_report_template().substitute(
        scan_date=_escape(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        repos_path=_escape(repos_path),
        total_findings=_escape(len(all_findings)),
        scanned_repos=_escape(scanned_repos),
        secret_types=_escape(secret_types),
        rows="".join(rows),
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html_report, encoding="utf-8")
    return output_path


def sanitize_finding_for_cloud(finding: dict[str, Any]) -> dict[str, Any]:
    """Return a cloud-safe finding record without raw source fragments or full secret values."""
    sanitized = {key: value for key, value in finding.items() if key not in {"Secret", "Match"}}
    secret_value = finding.get("Secret") or finding.get("Match")
    if secret_value:
        sanitized["SecretRedacted"] = redact_secret(str(secret_value))
    return sanitized


def build_json_report(
    all_findings: list[dict[str, Any]],
    repos_path: Path,
    eng_id: str | None = None,
) -> dict[str, Any]:
    scanned_repos = len(set(f.get("repo") for f in all_findings if f.get("repo")))
    secret_types = len(set(f.get("RuleID") for f in all_findings if f.get("RuleID")))
    findings_items = [sanitize_finding_for_cloud(finding) for finding in all_findings]
    report = {
        "schema": "cloudvisor.secret-scan-report.v1",
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "repos_path": str(repos_path),
        "summary": {
            "total_findings": len(findings_items),
            "repositories_affected": scanned_repos,
            "secret_types": secret_types,
        },
        "findings": {"items": findings_items},
    }
    if eng_id:
        report["engagement_id"] = eng_id
    return report


def write_json_report(report_data: dict[str, Any], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")
    return output_path


def _message_size_bytes(payload: dict[str, Any]) -> int:
    return len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def build_sqs_message_chunks(report_data: dict[str, Any]) -> list[dict[str, Any]]:
    findings_data = report_data.get("findings", [])
    if isinstance(findings_data, dict):
        findings = findings_data.get("items", [])
    else:
        findings = findings_data

    static_fields = {
        "schema": report_data.get("schema"),
        "generated_at": report_data.get("generated_at"),
        "repos_path": report_data.get("repos_path"),
        "summary": report_data.get("summary"),
    }
    if report_data.get("engagement_id"):
        static_fields["engagement_id"] = report_data.get("engagement_id")

    def findings_block(items: list[dict[str, Any]]) -> dict[str, Any]:
        return {"items": items}

    if not findings:
        return [{**static_fields, "part_number": 1, "total_parts": 1, "findings": findings_block([])}]

    chunks: list[list[dict[str, Any]]] = []
    current_chunk: list[dict[str, Any]] = []

    for finding in findings:
        candidate_chunk = [*current_chunk, finding]
        candidate_payload = {
            **static_fields,
            "part_number": 1,
            "total_parts": 1,
            "findings": findings_block(candidate_chunk),
        }
        if _message_size_bytes(candidate_payload) <= MAX_SQS_MESSAGE_BYTES:
            current_chunk = candidate_chunk
            continue

        if not current_chunk:
            raise ScannerError("A single finding exceeds the SQS message size limit (256KB).")

        chunks.append(current_chunk)
        current_chunk = [finding]

    if current_chunk:
        chunks.append(current_chunk)

    total_parts = len(chunks)
    return [
        {
            **static_fields,
            "part_number": index + 1,
            "total_parts": total_parts,
            "findings": findings_block(chunk),
        }
        for index, chunk in enumerate(chunks)
    ]


def publish_report_to_sqs_no_auth(queue_url: str, report_data: dict[str, Any]) -> int:
    def post_sqs(request: Request) -> Any:
        try:
            return urlopen(request, timeout=20)
        except URLError as exc:
            reason = getattr(exc, "reason", None)
            if not isinstance(reason, ssl.SSLCertVerificationError):
                raise
            try:
                import certifi  # type: ignore
            except ImportError as import_exc:
                raise ScannerError(
                    "TLS certificate verification failed while publishing to SQS.\n"
                    "Install Python certificates, install certifi, or provide a Python env "
                    "with valid CA trust.\n"
                    "macOS fix (Framework Python): run "
                    "'/Applications/Python 3.12/Install Certificates.command'"
                ) from import_exc
            ssl_context = ssl.create_default_context(cafile=certifi.where())
            return urlopen(request, timeout=20, context=ssl_context)

    messages = build_sqs_message_chunks(report_data)
    for message in messages:
        message_body = json.dumps(message, separators=(",", ":"), ensure_ascii=False)
        payload = urlencode(
            {
                "Action": "SendMessage",
                "Version": SQS_API_VERSION,
                "MessageBody": message_body,
            }
        ).encode("utf-8")
        request = Request(queue_url, data=payload, method="POST")
        request.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            with post_sqs(request) as response:
                status = getattr(response, "status", 200)
                if status < 200 or status >= 300:
                    raise ScannerError(f"SQS publish failed with status code {status}")
        except HTTPError as exc:
            details = exc.read().decode("utf-8", errors="replace")
            raise ScannerError(f"SQS publish failed ({exc.code} {exc.reason}): {details}") from exc
        except URLError as exc:
            raise ScannerError(f"SQS publish failed: {exc}") from exc
    return len(messages)


def get_repositories(repos_path: Path) -> list[Path]:
    repositories = [item for item in repos_path.iterdir() if item.is_dir()]
    return sorted(repositories, key=lambda item: item.name.lower())


def resolve_gitleaks_path(custom_path: Path | None, script_dir: Path) -> Path:
    if custom_path is not None:
        if not custom_path.exists():
            raise ScannerError(f"Provided gitleaks path does not exist: {custom_path}")
        return custom_path

    binary_name = "gitleaks.exe" if os.name == "nt" else "gitleaks"
    local_binary = script_dir / binary_name
    if local_binary.exists():
        return local_binary

    path_binary = shutil.which("gitleaks")
    if path_binary:
        return Path(path_binary)

    return download_gitleaks(script_dir)


def main() -> int:
    global COLOR_ENABLED
    args = parse_args()
    COLOR_ENABLED = should_use_color(args.color)
    repos_path = args.repos_path.expanduser().resolve()
    output_path = args.output.expanduser().resolve()
    json_output_path = args.json_output.expanduser().resolve() if args.json_output else None
    script_dir = Path(__file__).resolve().parent

    if not repos_path.exists() or not repos_path.is_dir():
        raise ScannerError(f"Invalid repositories path: {repos_path}")

    repositories = get_repositories(repos_path)
    if not repositories:
        raise ScannerError(f"No repositories found in: {repos_path}")

    gitleaks_path = resolve_gitleaks_path(args.gitleaks_path, script_dir)

    all_findings: list[dict[str, Any]] = []
    include_git_history = not args.no_git_history

    for repo in repositories:
        print(colorize(f"Scanning repository: {repo}", ANSI_CYAN))
        repo_findings = scan_repo(gitleaks_path, repo, include_git_history)
        all_findings.extend(repo_findings)

    report_json = build_json_report(all_findings, repos_path, args.eng_id)

    privacy_note = colorize(
        "(Raw source code and full secret values are never published)",
        ANSI_GREEN,
    )
    print(colorize("Publishing redacted report to Cloudvisor ", ANSI_CYAN) + privacy_note + colorize("...", ANSI_CYAN))
    publish_report_to_sqs_no_auth(DEFAULT_SQS_URL, report_json)
    print(colorize("Redacted report securely published to Cloudvisor.", ANSI_GREEN))

    report_path = generate_html_report(all_findings, repos_path, output_path)
    print(colorize(f"Report generated: {report_path}", ANSI_GREEN))

    if json_output_path is not None:
        json_report_path = write_json_report(report_json, json_output_path)
        print(colorize(f"JSON report generated: {json_report_path}", ANSI_GREEN))

    finding_count = len(all_findings)
    if finding_count:
        print(colorize(f"Total secrets found: {finding_count}", ANSI_YELLOW))
    else:
        print(colorize("Total secrets found: 0", ANSI_GREEN))

    # Return non-zero if findings exist for pipeline-friendly behavior.
    return 1 if all_findings else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ScannerError as exc:
        print(colorize(f"Error: {exc}", ANSI_RED), file=sys.stderr)
        raise SystemExit(2)
