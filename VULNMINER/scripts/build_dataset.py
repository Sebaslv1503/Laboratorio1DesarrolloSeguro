"""SEMMA Sample: normaliza fuentes públicas y construye el dataset trazable."""
from __future__ import annotations

import argparse
import csv
import hashlib
import re
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from vulnminer.catalog import API_CWE, OWASP_CWE

SCHEMA = [
    "record_id",
    "code",
    "language",
    "label",
    "cwe",
    "owasp_categories",
    "api_categories",
    "provenance",
    "source_id",
    "split_group",
    "synthetic",
]

SEMGREP_EXTENSIONS = {
    ".py": "Python",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".mjs": "JavaScript",
    ".cjs": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".java": "Java",
    ".dockerfile": "Configuration",
    ".properties": "Configuration",
    ".xml": "Configuration",
    ".json": "Configuration",
}

CONTROLLED_CONFIG_CASES = [
    (
        16,
        True,
        "Configuration",
        "management:\n  endpoints:\n    web:\n      exposure:\n        include: '*'\nserver:\n  error:\n    include-stacktrace: always\n    include-message: always",
    ),
    (
        16,
        True,
        "Configuration",
        "spring.datasource.url=jdbc:postgresql://db:5432/app\nmanagement.endpoints.web.exposure.include=*\nmanagement.endpoint.health.show-details=always\nserver.error.include-stacktrace=always",
    ),
    (
        798,
        True,
        "Configuration",
        "spring:\n  datasource:\n    username: admin\n    password: SuperSecretPassword123!\napp:\n  jwt:\n    secret: hardcoded-jwt-signing-secret-key-2026",
    ),
    (
        250,
        True,
        "Configuration",
        "services:\n  api:\n    image: node:20\n    privileged: true\n    network_mode: host\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock",
    ),
    (
        942,
        True,
        "Configuration",
        "cors:\n  allowed-origins: '*'\n  allow-credentials: true\n  allowed-methods: '*'\n  allowed-headers: '*'",
    ),
    (
        16,
        False,
        "Configuration",
        "management:\n  endpoints:\n    web:\n      exposure:\n        include: health,info\nserver:\n  error:\n    include-stacktrace: never\n    include-message: never",
    ),
    (
        798,
        False,
        "Configuration",
        "spring:\n  datasource:\n    username: ${DB_USER}\n    password: ${DB_PASSWORD}\napp:\n  jwt:\n    secret: ${JWT_SIGNING_KEY}",
    ),
    (
        250,
        False,
        "Configuration",
        "services:\n  api:\n    image: node:20-alpine\n    user: '1000:1000'\n    read_only: true\n    security_opt:\n      - no-new-privileges:true",
    ),
    (
        942,
        False,
        "Configuration",
        "cors:\n  allowed-origins:\n    - https://portal.example.org\n  allow-credentials: true\n  allowed-methods: GET,POST",
    ),
]

RULEID_RE = re.compile(r"(?:#|//|<!--|--)\s*ruleid\s*:", re.I)
OK_RE = re.compile(r"(?:#|//|<!--|--)\s*ok\s*:", re.I)
ANY_MARKER_RE = re.compile(r"(?:#|//|<!--|--)\s*(?:todo)?(?:ruleid|ok)\s*:", re.I)


def clean_benchmark_java(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", " ", source, flags=re.S)
    source = re.sub(r"(?m)^\s*//.*$", " ", source)
    source = re.sub(r"\bBenchmarkTest\d+\b", "BenchmarkCase", source)
    source = re.sub(
        r"/(?:pathtraver|sqli|xss|cmdi|crypto|hash|weakrand|trustbound|securecookie|ldapi|xpathi)-\d+/",
        "/case/",
        source,
        flags=re.I,
    )
    source = re.sub(r"(?m)^\s*package\s+[^;]+;\s*$", "", source)
    return re.sub(r"\n{3,}", "\n\n", source).strip()


def clean_benchmark_python(source: str) -> str:
    source = re.sub(r"'''[\s\S]*?'''", "", source, count=1)
    source = re.sub(r'"""[\s\S]*?"""', "", source, count=1)
    source = re.sub(r"(?m)^\s*#.*$", "", source)
    source = re.sub(r"\bBenchmarkTest\d+\b", "BenchmarkCase", source)
    source = re.sub(
        r"(?:/benchmark/|web/)(?:pathtraver|sqli|xss|cmdi|crypto|hash|weakrand|trustbound|securecookie|ldapi|xpathi|codeinj|deserialization|redirect|xxe)-\d+/",
        "/case/",
        source,
        flags=re.I,
    )
    return re.sub(r"\n{3,}", "\n\n", source).strip()


def make_row(
    code: str,
    language: str,
    vulnerable: bool,
    cwes: list[int],
    provenance: str,
    source_id: str,
    group: str,
    synthetic: bool,
) -> dict:
    code = code.strip()
    primary_cwe = cwes[0] if cwes else None
    ow: list[str] = []
    api: list[str] = []
    if vulnerable:
        for cwe in cwes:
            for tag in OWASP_CWE.get(cwe, ()):
                if tag not in ow:
                    ow.append(tag)
            for tag in API_CWE.get(cwe, ()):
                if tag not in api:
                    api.append(tag)
    digest = hashlib.sha256(
        (code + "\0" + str(primary_cwe) + "\0" + str(vulnerable)).encode()
    ).hexdigest()[:16]
    return {
        "record_id": digest,
        "code": code,
        "language": language,
        "label": "vulnerable" if vulnerable else "safe",
        "cwe": primary_cwe or "",
        "owasp_categories": ";".join(sorted(ow)),
        "api_categories": ";".join(sorted(api)),
        "provenance": provenance,
        "source_id": source_id,
        "split_group": group,
        "synthetic": bool(synthetic),
    }


def extract_benchmark_java(benchmark_root: Path) -> list[dict]:
    results = benchmark_root / "expectedresults-1.2.csv"
    source_root = benchmark_root / "src/main/java/org/owasp/benchmark/testcode"
    if not results.is_file() or not source_root.is_dir():
        raise FileNotFoundError(
            "BenchmarkJava esperado con expectedresults-1.2.csv y testcode/."
        )
    rows = []
    with results.open(encoding="utf-8-sig", newline="") as stream:
        for test, category, expected, cwe_text in csv.reader(
            line for line in stream if not line.startswith("#")
        ):
            code_path = source_root / f"{test}.java"
            if not code_path.is_file():
                continue
            code = clean_benchmark_java(
                code_path.read_text(encoding="utf-8", errors="replace")
            )
            rows.append(
                make_row(
                    code,
                    "Java",
                    expected.lower() == "true",
                    [int(cwe_text)],
                    "OWASP Benchmark Java 1.2",
                    test,
                    f"BenchmarkJava:{test}",
                    False,
                )
            )
    return rows


def extract_benchmark_python(benchmark_root: Path) -> list[dict]:
    csv_candidates = sorted(benchmark_root.glob("expectedresults-*.csv"))
    source_root = benchmark_root / "testcode"
    if not csv_candidates or not source_root.is_dir():
        raise FileNotFoundError(
            "BenchmarkPython esperado con expectedresults-*.csv y testcode/."
        )
    rows = []
    with csv_candidates[0].open(encoding="utf-8-sig", newline="") as stream:
        for test, category, expected, cwe_text in csv.reader(
            line for line in stream if not line.startswith("#")
        ):
            code_path = source_root / f"{test}.py"
            if not code_path.is_file():
                continue
            code = clean_benchmark_python(
                code_path.read_text(encoding="utf-8", errors="replace")
            )
            if len(re.sub(r"\s+", "", code)) < 30:
                continue
            rows.append(
                make_row(
                    code,
                    "Python",
                    expected.lower() == "true",
                    [int(cwe_text)],
                    "OWASP Benchmark Python 0.1",
                    test,
                    f"BenchmarkPython:{test}",
                    False,
                )
            )
    return rows


def _semgrep_language(path: Path) -> str | None:
    ext = path.suffix.lower()
    if ext in SEMGREP_EXTENSIONS:
        return SEMGREP_EXTENSIONS[ext]
    if "dockerfile" in path.name.lower():
        return "Configuration"
    if ext in {".yml", ".yaml"}:
        return "Configuration"
    return None


SECRET_PREFIX_SANITIZERS = [
    (re.compile(r"\b[sr]k_(?:live|test)_[0-9a-zA-Z]{16,}\b"), "EXAMPLE_SECRET_KEY_PLACEHOLDER_0000"),
    (re.compile(r"\bgh[pousr]_[0-9a-zA-Z]{20,}\b"), "EXAMPLE_TOKEN_PLACEHOLDER_0000"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "EXAMPLE_CLOUD_KEY_0000"),
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{30,}\b"), "EXAMPLE_API_KEY_PLACEHOLDER_0000"),
    (re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b"), "EXAMPLE_CHAT_TOKEN_0000"),
    (re.compile(r"\bSG\.[0-9A-Za-z\-_]{16,}\.[0-9A-Za-z\-_]{16,}\b"), "EXAMPLE_MAIL_KEY_0000"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "-----BEGIN EXAMPLE KEY-----"),
    (re.compile(r"-----END [A-Z ]*PRIVATE KEY-----"), "-----END EXAMPLE KEY-----"),
]


def _sanitize_provider_tokens(text: str) -> str:
    for rx, replacement in SECRET_PREFIX_SANITIZERS:
        text = rx.sub(replacement, text)
    return text


def _clean_semgrep_snippet(lines: list[str]) -> str:
    cleaned = []
    for line in lines:
        if ANY_MARKER_RE.search(line):
            continue
        cleaned.append(line)
    text = re.sub(r"\n{3,}", "\n\n", "\n".join(cleaned)).strip()
    return _sanitize_provider_tokens(text)


def extract_semgrep_rules(semgrep_root: Path) -> list[dict]:
    if not semgrep_root.is_dir():
        raise FileNotFoundError(f"No existe el directorio semgrep-rules: {semgrep_root}")
    rows = []
    for yml in sorted(semgrep_root.rglob("*.yaml")):
        rule_text = yml.read_text(encoding="utf-8", errors="replace")
        raw_cwes = [int(m) for m in re.findall(r"CWE-(\d+)", rule_text)]
        mapped_cwes = []
        for cwe in raw_cwes:
            if (cwe in OWASP_CWE or cwe in API_CWE) and cwe not in mapped_cwes:
                mapped_cwes.append(cwe)
        if not mapped_cwes:
            continue

        stem = yml.stem
        rel_rule = yml.relative_to(semgrep_root).as_posix()
        split_group = f"semgrep:{rel_rule}"

        for candidate in sorted(yml.parent.iterdir()):
            if (
                not candidate.is_file()
                or candidate == yml
                or candidate.name.endswith(".fixed")
            ):
                continue
            if not (candidate.stem == stem or candidate.name.startswith(stem + ".")):
                continue
            lang = _semgrep_language(candidate)
            if not lang:
                continue

            lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
            markers: list[tuple[int, str]] = []
            for idx, line in enumerate(lines):
                if RULEID_RE.search(line):
                    markers.append((idx, "vulnerable"))
                elif OK_RE.search(line):
                    markers.append((idx, "safe"))
                elif ANY_MARKER_RE.search(line):
                    markers.append((idx, "skip"))
            if not markers:
                continue

            rel_test = candidate.relative_to(semgrep_root).as_posix()
            for pos, (line_idx, kind) in enumerate(markers):
                if kind == "skip":
                    continue
                prev_marker = markers[pos - 1][0] if pos > 0 else -1
                next_marker = (
                    markers[pos + 1][0] if pos + 1 < len(markers) else len(lines)
                )
                start = max(prev_marker + 1, line_idx - 4)
                end = min(next_marker, line_idx + 8)
                snippet = _clean_semgrep_snippet(lines[start:end])
                if len(re.sub(r"\s+", "", snippet)) < 25:
                    continue
                rows.append(
                    make_row(
                        snippet,
                        lang,
                        kind == "vulnerable",
                        mapped_cwes,
                        "Semgrep Community Rules",
                        f"semgrep:{rel_test}:L{line_idx + 1}",
                        split_group,
                        False,
                    )
                )
    return rows


def load_preserved_rows(existing_csv: Path) -> list[dict]:
    df = pd.read_csv(existing_csv).fillna("")
    keep = df[
        df["provenance"].isin(
            {"OWASP Benchmark Java 1.2", "Dataset profesor (muestra deduplicada)"}
        )
    ]
    rows = []
    for _, item in keep.iterrows():
        cwe_val = int(item["cwe"]) if str(item["cwe"]).strip().isdigit() else None
        cwes = [cwe_val] if cwe_val else []
        vulnerable = str(item["label"]).strip().lower() == "vulnerable"
        source_id = str(item["source_id"])
        provenance = str(item["provenance"])
        group = (
            f"BenchmarkJava:{source_id}"
            if provenance == "OWASP Benchmark Java 1.2"
            else str(item["split_group"])
        )
        rows.append(
            make_row(
                str(item["code"]),
                str(item["language"]),
                vulnerable,
                cwes,
                provenance,
                source_id,
                group,
                False,
            )
        )
    return rows


def build(
    benchmark_java: Path | None,
    benchmark_python: Path | None,
    semgrep_root: Path | None,
    teacher_csv: Path | None,
    existing_csv: Path | None,
    output: Path,
) -> pd.DataFrame:
    rows: list[dict] = []

    if benchmark_java:
        rows.extend(extract_benchmark_java(benchmark_java))
    elif existing_csv and existing_csv.is_file():
        rows.extend(load_preserved_rows(existing_csv))

    if teacher_csv and teacher_csv.is_file():
        teacher = pd.read_csv(teacher_csv)
        for i, item in teacher.drop_duplicates("Code Snippet").iterrows():
            kind = str(item["Vulnerability Type"]).strip().lower()
            cwe = 89 if kind in {"sqli", "sql injection"} else 79 if kind == "xss" else None
            if cwe:
                rows.append(
                    make_row(
                        str(item["Code Snippet"]),
                        "JavaScript" if cwe == 79 else "Python",
                        True,
                        [cwe],
                        "Dataset profesor (muestra deduplicada)",
                        f"teacher:{i}",
                        f"teacher:{kind}",
                        False,
                    )
                )

    if benchmark_python:
        rows.extend(extract_benchmark_python(benchmark_python))

    if semgrep_root:
        rows.extend(extract_semgrep_rules(semgrep_root))

    for idx, (cwe, vulnerable, lang, code) in enumerate(CONTROLLED_CONFIG_CASES):
        rows.append(
            make_row(
                code,
                lang,
                vulnerable,
                [cwe],
                "synthetic-controlled",
                f"controlled:config:{cwe}:{idx}",
                f"controlled:config:{idx}",
                True,
            )
        )

    data = (
        pd.DataFrame(rows, columns=SCHEMA)
        .drop_duplicates(subset=["code", "label", "cwe"], keep="first")
        .reset_index(drop=True)
    )
    data.to_csv(output, index=False, encoding="utf-8")
    return data


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--benchmark-root", type=Path, help="Ruta a OWASP BenchmarkJava")
    parser.add_argument(
        "--benchmark-python-root", type=Path, help="Ruta a OWASP BenchmarkPython"
    )
    parser.add_argument(
        "--semgrep-root", type=Path, help="Ruta a semgrep/semgrep-rules"
    )
    parser.add_argument("--teacher-csv", type=Path, help="CSV del docente")
    parser.add_argument(
        "--existing-csv",
        type=Path,
        help="CSV curado previo para conservar filas de BenchmarkJava/docente si no se pasa --benchmark-root",
    )
    parser.add_argument("--output", type=Path, default=ROOT / "data/vulnerabilities.csv")
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    data = build(
        args.benchmark_root,
        args.benchmark_python_root,
        args.semgrep_root,
        args.teacher_csv,
        args.existing_csv,
        args.output,
    )
    print(f"Escritos {len(data)} registros: {data.label.value_counts().to_dict()}")
    print("Fuentes:", data.provenance.value_counts().to_dict())
    print("Lenguajes:", data.language.value_counts().to_dict())


if __name__ == "__main__":
    main()
