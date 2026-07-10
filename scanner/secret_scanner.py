import argparse
import os
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional

SECRET_PATTERNS = {
    "GitHub personal access token": re.compile(r"ghp_[A-Za-z0-9_]{36}"),
    "GitHub PAT (classic)": re.compile(r"gh[a-zA-Z0-9_]{36}"),
    "AWS access key ID": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS secret access key": re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"),
    "Slack webhook URL": re.compile(r"https://hooks\.slack\.com/services/[A-Z0-9]{9,}/[A-Z0-9]{9,}/[A-Za-z0-9]{24,}"),
    "Stripe secret key": re.compile(r"sk_live_[A-Za-z0-9]{24,}"),
    "Generic API key": re.compile(r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*[\"']?[A-Za-z0-9\-_=]{16,}[\"']?"),
    "Database password URI": re.compile(r"(?i)(?:postgres|mysql|mongodb|redis|mssql)://[^\s:@]+:[^\s@]+@"),
}

TEXT_EXTENSIONS = {
    ".py",
    ".txt",
    ".md",
    ".json",
    ".yaml",
    ".yml",
    ".env",
    ".ini",
    ".conf",
    ".cfg",
    ".dockerfile",
    ".gitignore",
}

EXCLUDE_DIRS = {"node_modules", ".git", "venv", "__pycache__", ".idea", ".venv"}


class Finding(Dict[str, Optional[str]]):
    pass


class SecretScanner:
    """Scans files for high-risk secret patterns."""

    def __init__(self) -> None:
        self.patterns = SECRET_PATTERNS

    def scan_file(self, file_path: Path) -> List[Finding]:
        findings: List[Finding] = []
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return findings

        for pattern_name, pattern in self.patterns.items():
            for match in pattern.finditer(text):
                line_number = text.count("\n", 0, match.start()) + 1
                excerpt = self._format_excerpt(text, match.start(), match.end())
                findings.append(
                    {
                        "file": str(file_path),
                        "line": str(line_number),
                        "pattern": pattern_name,
                        "match": match.group(0),
                        "excerpt": excerpt,
                    }
                )
        return findings

    def scan_path(self, path: Path) -> List[Finding]:
        results: List[Finding] = []
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            for name in files:
                file_path = Path(root) / name
                if not self.is_text_file(file_path):
                    continue
                results.extend(self.scan_file(file_path))
        return results

    @staticmethod
    def is_text_file(file_path: Path) -> bool:
        if file_path.suffix.lower() in TEXT_EXTENSIONS:
            return True
        try:
            with file_path.open("rb") as fh:
                sample = fh.read(8192)
            if b"\0" in sample:
                return False
            return True
        except OSError:
            return False

    @staticmethod
    def _format_excerpt(text: str, start: int, end: int, width: int = 40) -> str:
        prefix = text[max(0, start - width) : start].replace("\n", " ")
        secret_text = text[start:end].replace("\n", " ")
        suffix = text[end : min(len(text), end + width)].replace("\n", " ")
        return f"{prefix}{secret_text}{suffix}"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Local secret scanning POC for GitHub-style secret detection.")
    parser.add_argument("--path", default=".", help="Path to scan for secrets.")
    parser.add_argument("--summary", action="store_true", help="Print a summary only.")
    args = parser.parse_args(argv)

    scanner = SecretScanner()
    findings = scanner.scan_path(Path(args.path))

    if not findings:
        print("✅ No matching secrets found in the scanned path.")
        return 0

    print("🚨 Secret scanning results:")
    for finding in findings:
        print(
            f"- {finding['file']}:{finding['line']} | {finding['pattern']}\n"
            f"  match: {finding['match']}\n"
            f"  excerpt: {finding['excerpt']}\n"
        )

    if args.summary:
        summary: Dict[str, int] = {}
        for finding in findings:
            summary[finding["pattern"]] = summary.get(finding["pattern"], 0) + 1
        print("\nSummary:")
        for pattern_name, count in summary.items():
            print(f"- {pattern_name}: {count}")

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
